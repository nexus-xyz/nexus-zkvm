use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;

use crate::{
    column::Column::{self, *},
    extensions::ExtensionsConfig,
    trace::eval::trace_eval,
    traits::MachineChip,
};

use super::{
    gadget::{constrain_mul_partial_product, constrain_values_equal, constrain_zero_word},
    nexani::{divu_limb, mull_limb},
};

pub struct DivuRemuChip;

impl MachineChip for DivuRemuChip {
    fn fill_main_trace(
        traces: &mut crate::trace::TracesBuilder,
        row_idx: usize,
        vm_step: &Option<crate::trace::ProgramStep>, // None for padding
        _side_note: &mut crate::trace::sidenote::SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };

        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::DIVU) | Some(BuiltinOpcode::REMU)
        ) {
            return;
        }

        let value_a = vm_step
            .get_result()
            .expect("DIVU or REMU must have a result");
        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;
        let (remainder, quotient) = if value_c == [0, 0, 0, 0] {
            // Division by zero case
            let quotient = [0xFF, 0xFF, 0xFF, 0xFF];
            let remainder = value_b;
            (remainder, quotient)
        } else {
            // Normal division case
            let quotient = u32::from_le_bytes(value_b)
                .wrapping_div(u32::from_le_bytes(value_c))
                .to_le_bytes();
            let remainder = u32::from_le_bytes(value_b)
                .wrapping_rem(u32::from_le_bytes(value_c))
                .to_le_bytes();
            (remainder, quotient)
        };

        if vm_step.step.instruction.opcode.builtin() == Some(BuiltinOpcode::DIVU) {
            assert_eq!(quotient, value_a, "DIVU result is incorrect");
        } else {
            assert_eq!(remainder, value_a, "REMU result is incorrect");
        }
        // The quotient and remainder are are committed to the trace
        traces.fill_columns(row_idx, quotient, Quotient);

        // Calculate t = quotient * divisor using mul_limb to get intermediate values
        let mul_result = mull_limb(u32::from_le_bytes(quotient), u32::from_le_bytes(value_c));

        // Fill in the intermediate values from mul_limb(quotient, divisor) into traces
        // These are needed for the multiplication constraints that verify t = quotient * divisor
        traces.fill_columns(row_idx, mul_result.carry_l[0], MulCarry0);
        traces.fill_columns(row_idx, mul_result.carry_l[1], MulCarry1);

        // MUL P1, P3' and P3'' in range [0, 2^16 - 1]
        traces.fill_columns(row_idx, mul_result.p1, MulP1);
        traces.fill_columns(row_idx, mul_result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, mul_result.p3_prime_prime, MulP3PrimePrime);

        // MUL Carry of P1, P3' and P3'' in {0, 1}
        traces.fill_columns(row_idx, mul_result.c1, MulC1);
        traces.fill_columns(row_idx, mul_result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, mul_result.c3_prime_prime, MulC3PrimePrime);

        traces.fill_columns(row_idx, value_c == [0, 0, 0, 0], IsDivideByZero);
        // Store t = quotient * divisor
        traces.fill_columns(row_idx, mul_result.a_l, HelperT);

        // Calculate the division results (remainder r, check value u)
        let divu_result = divu_limb(
            u32::from_le_bytes(quotient),  // quotient
            u32::from_le_bytes(remainder), // remainder
            u32::from_le_bytes(value_b),   // dividend
            u32::from_le_bytes(value_c),   // divisor
        );

        // Store r = dividend - (quotient * divisor)
        traces.fill_columns(row_idx, divu_result.r, Remainder);
        traces.fill_columns(row_idx, divu_result.r_borrow[0], RemainderBorrow);
        // Store u = divisor - r - 1
        traces.fill_columns(row_idx, divu_result.u, HelperU);
        traces.fill_columns(row_idx, divu_result.u_borrow[0], HelperUBorrow);

        // Store original values needed in constraints
        traces.fill_columns(row_idx, value_a, ValueA); // Quotient/Remainder (rd)
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_divu] = trace_eval!(trace_eval, IsDivu);
        let [is_remu] = trace_eval!(trace_eval, IsRemu);
        let [is_divide_by_zero] = trace_eval!(trace_eval, IsDivideByZero);
        let dividend = trace_eval!(trace_eval, ValueB);
        let divisor_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);

        // Check for is_divide_by_zero
        // (is_divu + is_remu) ⋅ is_divide_by_zero ⋅ (c_0 + c_1 + c_2 + c_3)
        constrain_zero_word(
            eval,
            is_divu.clone() + is_remu.clone(),
            is_divide_by_zero.clone(),
            divisor_c.clone(),
        );

        // Handle DIVU exception:If divide by zero is true, then the result of the division is 2^32 - 1
        // otherwise, the result of the division is the quotient
        eval.add_constraint(
            is_divu.clone()
                * ((E::F::one() - is_divide_by_zero.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone() * E::F::from(BaseField::from(0xFFFF))
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_divu.clone()
                * ((E::F::one() - is_divide_by_zero.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone() * E::F::from(BaseField::from(0xFFFF))
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
        // Handle REMU exception:If divide by zero is true, then the result of the remainder is the dividend
        // otherwise, the result of the remainder is the dividend
        eval.add_constraint(
            is_remu.clone()
                * ((E::F::one() - is_divide_by_zero.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone()
                        * (dividend[0].clone() + dividend[1].clone() * BaseField::from(1 << 8))
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_remu.clone()
                * ((E::F::one() - is_divide_by_zero.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone()
                        * (dividend[2].clone() + dividend[3].clone() * BaseField::from(1 << 8))
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );

        let quotient = trace_eval!(trace_eval, Quotient);
        let remainder = trace_eval!(trace_eval, Remainder);
        // Assert that the committed Quotient is equal to value_a
        constrain_values_equal(eval, is_divu.clone(), value_a.clone(), quotient.clone());
        // Assert that the committed Remainder is equal to value_a
        constrain_values_equal(eval, is_remu.clone(), value_a.clone(), remainder.clone());

        // Now, we verify the committed quotient and remainder are correct
        // We do this by verifying the following constraints:
        // 1. t = quotient * divisor is in 32-bit range
        // 2. r = dividend - t >= 0 and r is equal to the committed remainder
        // 3. u = divisor - r - 1 >= 0 when c != 0

        // Assert that the multiplication of quotient * divisor fits within 32 bits
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * ((quotient[2].clone() + quotient[3].clone())
                    * (divisor_c[2].clone() + divisor_c[3].clone())
                    + quotient[1].clone() * divisor_c[3].clone()
                    + quotient[3].clone() * divisor_c[1].clone()),
        );

        // Assert the intermediate values are correct for the t = quotient * divisor calculation
        let p1 = trace_eval!(trace_eval, MulP1);
        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let [c1] = trace_eval!(trace_eval, MulC1);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);

        let z_0 = quotient[0].clone() * divisor_c[0].clone();
        let z_1 = quotient[1].clone() * divisor_c[1].clone();
        let z_2 = quotient[2].clone() * divisor_c[2].clone();
        let z_3 = quotient[3].clone() * divisor_c[3].clone();

        // (is_divu + is_remu) * (P3_prime + c3_prime * 2^16 - (|b|_0 + |b|_3) * (|c|_0 + |c|_3) + z_0 + z_3)
        constrain_mul_partial_product(
            eval,
            is_divu.clone() + is_remu.clone(),
            p3_prime.clone(),
            c3_prime.clone(),
            quotient[0].clone(),
            quotient[3].clone(),
            divisor_c[0].clone(),
            divisor_c[3].clone(),
            z_0.clone(),
            z_3.clone(),
        );

        // (is_divu + is_remu) * (P3_prime_prime + c3_prime_prime * 2^16 - (|b|_1 + |b|_2) * (|c|_1 + |c|_2) + z_1 + z_2)
        constrain_mul_partial_product(
            eval,
            is_divu.clone() + is_remu.clone(),
            p3_prime_prime.clone(),
            c3_prime_prime.clone(),
            quotient[1].clone(),
            quotient[2].clone(),
            divisor_c[1].clone(),
            divisor_c[2].clone(),
            z_1.clone(),
            z_2.clone(),
        );

        // (is_divu + is_remu) * (P1 + c1 * 2^16 - (|b|_0 + |b|_1) * (|c|_0 + |c|_1) + z_0 + z_1)
        constrain_mul_partial_product(
            eval,
            is_divu.clone() + is_remu.clone(),
            p1.clone(),
            c1.clone(),
            quotient[0].clone(),
            quotient[1].clone(),
            divisor_c[0].clone(),
            divisor_c[1].clone(),
            z_0.clone(),
            z_1.clone(),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1] = trace_eval!(trace_eval, MulCarry1);

        let helper_t = trace_eval!(trace_eval, HelperT); // t = quotient * divisor

        // Constraint for low part of t = quotient * divisor
        // (is_divu + is_remu) ⋅ (z0 + P1_l ⋅ 2^8 − carry0 ⋅ 2^16 − |t|0 − |t|1 ⋅ 2^8)
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - helper_t[0].clone()
                    - helper_t[1].clone() * BaseField::from(1 << 8)),
        );

        // Constraint for high part of t = quotient * divisor
        // (is_divu + is_remu) *
        // (z_1 + P1_h + (b_0 + b_2) * (c_0 + c_2) - z_0 - z_2 + (P3_l_prime + P3_l_prime_prime + c_1) * 2^8 + carry_0 - carry_1 * 2^16 - |t|_2 - |t|_3 * 2^8)
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (z_1.clone()
                    + p1[1].clone()
                    + (quotient[0].clone() + quotient[2].clone())
                        * (divisor_c[0].clone() + divisor_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + mul_carry_0.clone()
                    - mul_carry_1.clone() * BaseField::from(1 << 16)
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    - helper_t[2].clone()
                    - helper_t[3].clone() * BaseField::from(1 << 8)),
        );

        let [remainder_borrow] = trace_eval!(trace_eval, RemainderBorrow); // borrow for r = dividend - t

        // Assert the calculation of r = dividend - t, rearranged as dividend = t + r
        // Low part: dividend_low + remainder_borrow0 * 2^16 = t_low + r_low
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * ((dividend[0].clone()
                    + dividend[1].clone() * BaseField::from(1 << 8)
                    + remainder_borrow.clone() * BaseField::from(1 << 16)) // remainder_borrow0 * 2^16
                   - (helper_t[0].clone()
                    + helper_t[1].clone() * BaseField::from(1 << 8)
                    + remainder[0].clone()
                    + remainder[1].clone() * BaseField::from(1 << 8))), // t_low + r_low
        );

        // High part: dividend_high = t_high + r_high + remainder_borrow0 (simplified)
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * ((dividend[2].clone()
                    + dividend[3].clone() * BaseField::from(1 << 8))
                   - remainder_borrow.clone() // remainder_borrow0
                   - (helper_t[2].clone()
                    + helper_t[3].clone() * BaseField::from(1 << 8)
                    + remainder[2].clone()
                    + remainder[3].clone() * BaseField::from(1 << 8))), // t_high + r_high
        );

        // Check u = c - r - 1 >= 0
        // Low part: c_low + helper_u_borrow0 * 2^16 = r_low + u_low + 1
        let helper_u = trace_eval!(trace_eval, HelperU); // u
        let [helper_u_borrow] = trace_eval!(trace_eval, HelperUBorrow); // borrow for c - r - 1
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (E::F::one() - is_divide_by_zero.clone())
                * ((divisor_c[0].clone() + divisor_c[1].clone() * BaseField::from(1 << 8)) // c_low
                   + helper_u_borrow.clone() * BaseField::from(1 << 16) // helper_u_borrow0 * 2^16
                   - remainder[0].clone() // r_low
                   - remainder[1].clone() * BaseField::from(1 << 8) // r_low
                   - E::F::one() // 1
                   - helper_u[0].clone()
                   - helper_u[1].clone() * BaseField::from(1 << 8)), // u_low
        );

        // High part: c_high = r_high + u_high + helper_u_borrow0 (simplified)
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (E::F::one() - is_divide_by_zero.clone())
                * ((divisor_c[2].clone() + divisor_c[3].clone() * BaseField::from(1 << 8)) // c_high
                    - remainder[2].clone() // r_high
                    - remainder[3].clone() * BaseField::from(1 << 8) // r_high
                    - helper_u_borrow.clone() // helper_u_borrow0
                    - helper_u[2].clone()
                    - helper_u[3].clone() * BaseField::from(1 << 8)), // u_high
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SubChip,
        },
        extensions::ExtensionsConfig,
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, sidenote::SideNote,
            PreprocessedTraces, TracesBuilder,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_divu_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Test basic division for DIVU
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10), // x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 3),  // x2 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2), // x3 = divu(10, 3) = 3
            // Test division by 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 42), // x4 = 42
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 1),  // x5 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 6, 4, 5), // x6 = divu(42, 1) = 42
            // Test division by 0 (should return 2^32-1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 5), // x7 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 9, 7, 8), // x9 = divu(5, 0) = 2^32-1
            // Test max value division
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1), // x11 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 10, 0, 1), // x10 = 2^32-1 (max u32)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 2), // x11 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 12, 10, 11), // x12 = divu(2^32-1, 2)
            // Test division where result is 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 3), // x13 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 10), // x14 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 15, 13, 14), // x15 = divu(3, 10) = 0
            // Test division where divisor equals dividend
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 0, 7), // x16 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, 7), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 18, 16, 17), // x18 = divu(7, 7) = 1
            // Test division with large values that don't overflow
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 2), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 20, 0, 3), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 19, 0, 19), // x19 = 2^32-2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 20, 0, 20), // x20 = 2^32-3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 21, 19, 20), // x21 = divu(2^32-2, 2^32-3)
            // Test division where remainder is exactly 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 100), // x22 = 100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 25),  // x23 = 25
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 24, 22, 23), // x24 = divu(100, 25) = 4
        ]);
        vec![basic_block]
    }

    fn setup_basic_block_remu_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Test basic remainder for REMU
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10), // x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 3),  // x2 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 3, 1, 2), // x3 = remu(10, 3) = 1
            // Test remainder when divisor is 1 (should always be 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 42), // x4 = 42
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 1),  // x5 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 6, 4, 5), // x6 = remu(42, 1) = 0
            // Test remainder by 0 (should return dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 5), // x7 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 9, 7, 8), // x9 = remu(5, 0) = 5
            // Test max value remainder
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1), // x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 10, 0, 1), // x10 = 2^32-1 (max u32)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 2), // x11 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 12, 10, 11), // x12 = remu(2^32-1, 2) = 1
            // Test remainder where dividend < divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 3), // x13 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 10), // x14 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 15, 13, 14), // x15 = remu(3, 10) = 3
            // Test remainder where divisor equals dividend
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 0, 7), // x16 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, 7), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 18, 16, 17), // x18 = remu(7, 7) = 0
            // Test remainder with large values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 2), // x19 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 20, 0, 3), // x20 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 19, 0, 19), // x19 = 2^32-2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 20, 0, 20), // x20 = 2^32-3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 21, 19, 20), // x21 = remu(2^32-2, 2^32-3) = 2^32-2
            // Test remainder where remainder is exactly 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 100), // x22 = 100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 25),  // x23 = 25
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 24, 22, 23), // x24 = remu(100, 25) = 0
        ]);
        vec![basic_block]
    }

    fn test_k_trace_constrained_instructions(basic_block: Vec<BasicBlock>) {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            DivuRemuChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }

    #[test]
    fn test_k_trace_constrained_divu_instructions() {
        let basic_block = setup_basic_block_divu_ir();
        test_k_trace_constrained_instructions(basic_block);
    }

    #[test]
    fn test_k_trace_constrained_remu_instructions() {
        let basic_block = setup_basic_block_remu_ir();
        test_k_trace_constrained_instructions(basic_block);
    }

    fn setup_comprehensive_divu_remu_tests() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Setup useful constants
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1
            // --- Simple Power of 2 Tests ---
            // 8 / 4 = 2, 8 % 4 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 8), // x1 = 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 4), // x2 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 3, 1, 2), // x3 = 8/4 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 4, 1, 2), // x4 = 8%4 = 0
            // 16 / 8 = 2, 16 % 8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 16), // x5 = 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 6, 5, 1),  // x6 = 16/8 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 7, 5, 1),  // x7 = 16%8 = 0
            // 9 / 4 = 2, 9 % 4 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 9), // x8 = 9
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 9, 8, 2), // x9 = 9/4 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 10, 8, 2), // x10 = 9%4 = 1
            // --- Boundary Value Tests ---
            // 1 / 1 = 1, 1 % 1 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 11, 30, 30), // x11 = 1/1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 12, 30, 30), // x12 = 1%1 = 0
            // 0 / 5 = 0, 0 % 5 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 0), // x13 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 5), // x14 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIVU), 15, 13, 14), // x15 = 0/5 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REMU), 16, 13, 14), // x16 = 0%5 = 0
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_comprehensive_divu_remu() {
        let basic_block = setup_comprehensive_divu_remu_tests();
        test_k_trace_constrained_instructions(basic_block);
    }
}
