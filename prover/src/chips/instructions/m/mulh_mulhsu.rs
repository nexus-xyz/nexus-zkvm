use crate::extensions::ExtensionsConfig;
use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};
use nexus_vm::riscv::BuiltinOpcode;
use stwo_prover::core::fields::m31::BaseField;

use super::gadget::{
    constrain_absolute_32_bit, constrain_absolute_64_bit, constrain_mul_partial_product,
    constrain_sign_1_to_1, constrain_sign_2_to_1, constrain_values_equal, constrain_zero_word,
};
use super::nexani::{abs64_limb, abs_limb, mull_limb};

pub struct MulhMulhsuChip;

impl MachineChip for MulhMulhsuChip {
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
            Some(BuiltinOpcode::MULH) | Some(BuiltinOpcode::MULHSU)
        ) {
            return;
        }

        let is_mulhsu = matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::MULHSU)
        );

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // Commit the absolute value and carry of the operand B to the trace
        let abs_value_b = abs_limb(u32::from_le_bytes(value_b));
        traces.fill_columns(row_idx, abs_value_b.abs_limbs, ValueBAbs);
        traces.fill_columns(row_idx, abs_value_b.carry, ValueBAbsBorrow);
        traces.fill_columns(row_idx, abs_value_b.sgn, SgnB);

        // For MULHSU, operand C is treated as unsigned, so we don't compute its absolute value
        // For MULH, operand C is treated as signed, so we compute its absolute value
        let abs_value_c = if is_mulhsu {
            // For MULHSU, treat operand C as unsigned (no absolute value needed)
            let value_c_u32 = u32::from_le_bytes(value_c);
            let abs_limbs = value_c_u32.to_le_bytes();
            traces.fill_columns(row_idx, abs_limbs, ValueCAbs);
            abs_limbs
        } else {
            // For MULH, treat operand C as signed (compute absolute value)
            let abs_value_c = abs_limb(u32::from_le_bytes(value_c));
            traces.fill_columns(row_idx, abs_value_c.abs_limbs, ValueCAbs);
            traces.fill_columns(row_idx, abs_value_c.carry, ValueCAbsBorrow);
            traces.fill_columns(row_idx, abs_value_c.sgn, SgnC);
            abs_value_c.abs_limbs
        };

        let result = mull_limb(
            u32::from_le_bytes(abs_value_b.abs_limbs),
            u32::from_le_bytes(abs_value_c),
        );

        traces.fill_columns(row_idx, result.p1, MulP1);
        traces.fill_columns(row_idx, result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, result.p3_prime_prime, MulP3PrimePrime);
        traces.fill_columns(row_idx, result.p5, MulP5);

        traces.fill_columns(row_idx, result.c1, MulC1);
        traces.fill_columns(row_idx, result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, result.c3_prime_prime, MulC3PrimePrime);
        traces.fill_columns(row_idx, result.c5, MulC5);

        traces.fill_columns(row_idx, result.a_l, ValueAAbs);
        traces.fill_columns(row_idx, result.a_h, ValueAAbsHigh);

        traces.fill_columns(row_idx, result.carry_l[0], MulCarry0);
        traces.fill_columns(row_idx, result.carry_l[1], MulCarry1);
        traces.fill_columns(row_idx, result.carry_h[0], MulCarry2_0);
        traces.fill_columns(row_idx, result.carry_h[1], MulCarry2_1);
        traces.fill_columns(row_idx, result.carry_h[2], MulCarry3);

        let is_a_zero = result.a_l == [0, 0, 0, 0] && result.a_h == [0, 0, 0, 0];
        traces.fill_columns(row_idx, is_a_zero, IsAZero);

        let value_a_low = u32::from_le_bytes(value_b)
            .wrapping_mul(u32::from_le_bytes(value_c))
            .to_le_bytes();
        let value_a_high = vm_step
            .get_result()
            .expect("MULH/MULHSU must have a result");

        let abs_value_a = abs64_limb(
            u32::from_le_bytes(value_a_low),
            u32::from_le_bytes(value_a_high),
        );
        traces.fill_columns(row_idx, abs_value_a.sgn, SgnA);
        traces.fill_columns(row_idx, abs_value_a.carry_low, ValueAAbsBorrow);
        traces.fill_columns(row_idx, abs_value_a.carry_high, ValueAAbsBorrowHigh);

        traces.fill_columns(row_idx, value_a_low, ValueALow);
        traces.fill_columns(row_idx, value_a_high, ValueA);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_mulh] = trace_eval!(trace_eval, IsMulh);
        let [is_mulhsu] = trace_eval!(trace_eval, IsMulhsu);

        let abs_value_b = trace_eval!(trace_eval, ValueBAbs);
        let abs_value_b_borrow = trace_eval!(trace_eval, ValueBAbsBorrow);
        let value_b = trace_eval!(trace_eval, ValueB);
        let [sgn_b] = trace_eval!(trace_eval, SgnB);

        // Assert that the absolute value and carry of the operand B is correct. Applies to MULH and MULHSU.
        constrain_absolute_32_bit(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            sgn_b.clone(),
            value_b,
            abs_value_b.clone(),
            abs_value_b_borrow.clone(),
        );

        let abs_value_c = trace_eval!(trace_eval, ValueCAbs);
        let abs_value_c_borrow = trace_eval!(trace_eval, ValueCAbsBorrow);
        let value_c = trace_eval!(trace_eval, ValueC);
        let [sgn_c] = trace_eval!(trace_eval, SgnC);
        // Assert that the absolute value and carry of the operand C is correct. Applies to MULH only.
        constrain_absolute_32_bit(
            eval,
            is_mulh.clone(),
            sgn_c.clone(),
            value_c.clone(),
            abs_value_c.clone(),
            abs_value_c_borrow.clone(),
        );

        constrain_values_equal(
            eval,
            is_mulhsu.clone(),
            abs_value_c.clone(),
            value_c.clone(),
        );

        // Intermediate products
        let z_0 = abs_value_b[0].clone() * abs_value_c[0].clone();
        let z_1 = abs_value_b[1].clone() * abs_value_c[1].clone();
        let z_2 = abs_value_b[2].clone() * abs_value_c[2].clone();
        let z_3 = abs_value_b[3].clone() * abs_value_c[3].clone();

        let p1 = trace_eval!(trace_eval, MulP1);
        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let p5 = trace_eval!(trace_eval, MulP5);
        let [c1] = trace_eval!(trace_eval, MulC1);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);
        let [c5] = trace_eval!(trace_eval, MulC5);

        // (is_mulh + is_mulhsu) * [P1_l + P1_h*2^8 + c1*2^16 - (|b|_0 + |b|_1)*(|c|_0 + |c|_1) + z_0 + z_1]
        constrain_mul_partial_product(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            p1.clone(),
            c1.clone(),
            abs_value_b[0].clone(),
            abs_value_b[1].clone(),
            abs_value_c[0].clone(),
            abs_value_c[1].clone(),
            z_0.clone(),
            z_1.clone(),
        );

        // (is_mulh + is_mulhsu) * [P'3_l + P'3_h*2^8 + c'3*2^16 - (|b|_0 + |b|_3)*(|c|_0 + |c|_3) + z_0 + z_3]
        constrain_mul_partial_product(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            p3_prime.clone(),
            c3_prime.clone(),
            abs_value_b[0].clone(),
            abs_value_b[3].clone(),
            abs_value_c[0].clone(),
            abs_value_c[3].clone(),
            z_0.clone(),
            z_3.clone(),
        );

        // (is_mulh + is_mulhsu) * [P''3_l + P''3_h*2^8 + c''3*2^16 - (|b|_1 + |b|_2)*(|c|_1 + |c|_2) + z_1 + z_2]
        constrain_mul_partial_product(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            p3_prime_prime.clone(),
            c3_prime_prime.clone(),
            abs_value_b[1].clone(),
            abs_value_b[2].clone(),
            abs_value_c[1].clone(),
            abs_value_c[2].clone(),
            z_1.clone(),
            z_2.clone(),
        );

        // (is_mulh + is_mulhsu) * [P5_l + P5_h*2^8 + c5*2^16 - (|b|_2 + |b|_3)*(|c|_2 + |c|_3) + z_2 + z_3]
        constrain_mul_partial_product(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            p5.clone(),
            c5.clone(),
            abs_value_b[2].clone(),
            abs_value_b[3].clone(),
            abs_value_c[2].clone(),
            abs_value_c[3].clone(),
            z_2.clone(),
            z_3.clone(),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1] = trace_eval!(trace_eval, MulCarry1);
        let [mul_carry_2_0] = trace_eval!(trace_eval, MulCarry2_0);
        let [mul_carry_2_1] = trace_eval!(trace_eval, MulCarry2_1);
        let [mul_carry_3] = trace_eval!(trace_eval, MulCarry3);

        let abs_value_a_low = trace_eval!(trace_eval, ValueAAbs);
        let abs_value_a_high = trace_eval!(trace_eval, ValueAAbsHigh);

        // (is_mulh + is_mulhsu) * [z_0 + P1_l*2^8 - carry_0*2^16 - |a|_0 - |a|_1*2^8]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - abs_value_a_low[0].clone()
                    - abs_value_a_low[1].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) *
        // [z_1 + P1_h + (b_0 + b_2)*(c_0 + c_2) - z_0 - z_2 + (P'3_l + P''3_l + c_1)*2^8 + carry_0 - carry_1*2^16 - |a|_2 - |a|_3*2^8]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_1.clone()
                    + p1[1].clone()
                    + (abs_value_b[0].clone() + abs_value_b[2].clone())
                        * (abs_value_c[0].clone() + abs_value_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    + mul_carry_0.clone()
                    - mul_carry_1.clone() * BaseField::from(1 << 16)
                    - abs_value_a_low[2].clone()
                    - abs_value_a_low[3].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) * [z_2 + P'3_h + P''3_h + (b_1 + b_3)*(c_1 + c_3) - z_1 - z_3 +
        // (P5_l + c''3 + c'3)*2^8 + carry_1 - carry_2_0*2^16 - carry_2_1*2^17 - |a|_0 - |a|_1*2^8]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_2.clone()
                    + p3_prime[1].clone()
                    + p3_prime_prime[1].clone()
                    + (abs_value_b[1].clone() + abs_value_b[3].clone())
                        * (abs_value_c[1].clone() + abs_value_c[3].clone())
                    - z_1.clone()
                    - z_3.clone()
                    + (p5[0].clone() + c3_prime_prime.clone() + c3_prime.clone())
                        * BaseField::from(1 << 8)
                    + mul_carry_1
                    - mul_carry_2_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_2_1.clone() * BaseField::from(1 << 17)
                    - abs_value_a_high[0].clone()
                    - abs_value_a_high[1].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) * [z_3 + P5_h + c5*2^8 + carry_2_0 + carry_2_1*2^1 - carry_3*2^16 - |a|_2 - |a|_3*2^8]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_3.clone()
                    + p5[1].clone()
                    + c5.clone() * BaseField::from(1 << 8)
                    + mul_carry_2_0.clone()
                    + mul_carry_2_1.clone() * BaseField::from(1 << 1)
                    - mul_carry_3.clone() * BaseField::from(1 << 16)
                    - abs_value_a_high[2].clone()
                    - abs_value_a_high[3].clone() * BaseField::from(1 << 8)),
        );

        let [is_a_zero] = trace_eval!(trace_eval, IsAZero);
        constrain_zero_word(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            is_a_zero.clone(),
            abs_value_a_low.clone(),
        );
        constrain_zero_word(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            is_a_zero.clone(),
            abs_value_a_high.clone(),
        );

        let [sgn_a] = trace_eval!(trace_eval, SgnA);
        // The sign of the result depends on the sign of the valueB and valueC for MULH.
        constrain_sign_2_to_1(
            eval,
            is_mulh.clone(),
            sgn_a.clone(),
            is_a_zero.clone(),
            [sgn_b.clone(), sgn_c.clone()],
        );

        // The sign of the result depends on the sign of the valueB for MULHSU.
        constrain_sign_1_to_1(
            eval,
            is_mulhsu.clone(),
            sgn_a.clone(),
            is_a_zero.clone(),
            sgn_b.clone(),
        );

        let value_a = trace_eval!(trace_eval, ValueA);
        let value_a_low = trace_eval!(trace_eval, ValueALow);
        let abs_value_a_low_borrow = trace_eval!(trace_eval, ValueAAbsBorrow);
        let abs_value_a_high_borrow = trace_eval!(trace_eval, ValueAAbsBorrowHigh);
        // Check for absolute value of value_a is equal to abs_value_a_high
        constrain_absolute_64_bit(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            sgn_a.clone(),
            value_a_low,
            value_a,
            abs_value_a_low,
            abs_value_a_high,
            abs_value_a_low_borrow,
            abs_value_a_high_borrow,
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, LuiChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SrlChip, SubChip,
        },
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

    fn setup_basic_mulh_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Setup registers with various signed values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1
            // Positive values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 0), // x3 = 0
            // Negative values via ADDI + SUB
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1), // x4 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4),  // x4 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 7), // x5 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 5),  // x5 = -7
            // Edge cases
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 6, 0, 0x7FFFF), // x6 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 6, 0xFFF), // x6 = 0x7FFFFFFF (MAX_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 7, 0, 0x80000), // x7 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 8, 0, 1),       // x8 = 0x00001000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 30),      // x9 = -1 (alt)
            // --- MULH Tests ---
            // 1. Positive * Positive
            // 5 * 7 = 35 = 0x23. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 10, 1, 2), // x10 = mulh(5, 7) = 0
            // 2. Positive * Negative
            // 5 * (-1) = -5 = 0xFFFFFFFB. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 11, 1, 4), // x11 = mulh(5, -1) = -1
            // 3. Negative * Positive
            // (-7) * 5 = -35 = 0xFFFFFFDD. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 12, 5, 1), // x12 = mulh(-7, 5) = -1
            // 4. Negative * Negative
            // (-1) * (-7) = 7 = 0x7. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 13, 4, 5), // x13 = mulh(-1, -7) = 0
            // 5. Edge Cases
            // MAX_INT * MAX_INT
            // 0x7FFFFFFF * 0x7FFFFFFF = 0x3FFF_FFFF_0000_0001. Upper bits = 0x3FFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 14, 6, 6), // x14 = mulh(MAX_INT, MAX_INT)
            // MIN_INT * MIN_INT
            // 0x80000000 * 0x80000000 = 0x4000000000000000. Upper bits = 0x40000000.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 15, 7, 7), // x15 = mulh(MIN_INT, MIN_INT)
            // MIN_INT * (-1)
            // 0x80000000 * 0xFFFFFFFF = 0x80000000. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 16, 7, 4), // x16 = mulh(MIN_INT, -1)
            // MIN_INT * 1
            // 0x80000000 * 1 = 0x80000000. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 17, 7, 30), // x17 = mulh(MIN_INT, 1)
            // MAX_INT * (-1)
            // 0x7FFFFFFF * 0xFFFFFFFF = 0xFFFFFFFF80000001. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 18, 6, 4), // x18 = mulh(MAX_INT, -1)
            // 6. Zero Cases
            // 0 * 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 19, 3, 1), // x19 = mulh(0, 5) = 0
            // 5 * 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 20, 1, 3), // x20 = mulh(5, 0) = 0
            // 0 * (-7)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 21, 3, 5), // x21 = mulh(0, -7) = 0
            // (-7) * 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 22, 5, 3), // x22 = mulh(-7, 0) = 0
            // 7. Additional edge cases
            // 0x00001000 * 0x00001000 (boundary case)
            // 0x1000 * 0x1000 = 0x1000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 23, 8, 8), // x23 = mulh(0x1000, 0x1000) = 0
            // (-1) * (-1)
            // 0xFFFFFFFF * 0xFFFFFFFF = 0x00000001. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULH), 24, 4, 4), // x24 = mulh(-1, -1) = 0
        ]);
        vec![basic_block]
    }

    fn setup_basic_mulhsu_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Setup registers with various signed values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1
            // Positive values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 0), // x3 = 0
            // Negative values via ADDI + SUB
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1), // x4 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4),  // x4 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 7), // x5 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 5),  // x5 = -7
            // Edge cases
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 6, 0, 0x7FFFF), // x6 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 6, 0xFFF), // x6 = 0x7FFFFFFF (MAX_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 7, 0, 0x80000), // x7 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 8, 0, 1),       // x8 = 0x00001000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 30),      // x9 = -1 (alt)
            // Large unsigned values for second operand
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 25, 0, 1), // x25 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 25, 0, 25), // x25 = 0 - 1 = -1 = 0xFFFFFFFF (MAX_UINT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 26, 0, 0x80000), // x26 = 0x80000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 27, 0, 0x40000), // x27 = 0x40000000
            // --- MULHSU Tests ---
            // MULHSU treats first operand as signed, second as unsigned

            // 1. Positive signed * Small unsigned
            // 5 * 7 = 35 = 0x23. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 10, 1, 2), // x10 = mulhsu(5, 7) = 0
            // 2. Positive signed * Large unsigned (treated as positive)
            // 5 * 0xFFFFFFFF = 5 * 4294967295 = 21474836475 = 0x4FFFFFFFB
            // Upper bits = 0x4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 11, 1, 25), // x11 = mulhsu(5, MAX_UINT)
            // 3. Negative signed * Small unsigned
            // (-1) * 7 = -7 = 0xFFFFFFF9. Upper bits = 0xFFFFFFFF.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 12, 4, 2), // x12 = mulhsu(-1, 7)
            // 4. Negative signed * Large unsigned
            // (-1) * 0xFFFFFFFF = -4294967295 = 0xFFFFFFFF00000001
            // Upper bits = 0xFFFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 13, 4, 25), // x13 = mulhsu(-1, MAX_UINT)
            // 5. Negative signed * Medium unsigned
            // (-7) * 0x80000000 = -7 * 2147483648 = -15032385536 = 0xFFFFFFFCC8000000
            // Upper bits = 0xFFFFFFFC
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 14, 5, 26), // x14 = mulhsu(-7, 0x80000000)
            // 6. Edge Cases with MAX_INT and MIN_INT
            // MAX_INT * MAX_UINT
            // 0x7FFFFFFF * 0xFFFFFFFF = 2147483647 * 4294967295 = 9223372034707292160
            // = 0x7FFFFFFE80000001. Upper bits = 0x7FFFFFFE
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 15, 6, 25), // x15 = mulhsu(MAX_INT, MAX_UINT)
            // MIN_INT * MAX_UINT
            // 0x80000000 * 0xFFFFFFFF = -2147483648 * 4294967295 = -9223372034707292160
            // = 0x8000000180000000. Upper bits = 0x80000001
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 16, 7, 25), // x16 = mulhsu(MIN_INT, MAX_UINT)
            // MIN_INT * 0x80000000
            // 0x80000000 * 0x80000000 = -2147483648 * 2147483648 = -4611686018427387904
            // = 0xC000000000000000. Upper bits = 0xC0000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 17, 7, 26), // x17 = mulhsu(MIN_INT, 0x80000000)
            // MIN_INT * 1
            // 0x80000000 * 1 = -2147483648. Upper bits = 0xFFFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 18, 7, 30), // x18 = mulhsu(MIN_INT, 1)
            // MAX_INT * 0x80000000
            // 0x7FFFFFFF * 0x80000000 = 2147483647 * 2147483648 = 4611686016279904256
            // = 0x3FFFFFFF80000000. Upper bits = 0x3FFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 19, 6, 26), // x19 = mulhsu(MAX_INT, 0x80000000)
            // 7. Zero Cases
            // 0 * 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 20, 3, 1), // x20 = mulhsu(0, 5) = 0
            // 5 * 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 21, 1, 3), // x21 = mulhsu(5, 0) = 0
            // 0 * MAX_UINT
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 22, 3, 25), // x22 = mulhsu(0, MAX_UINT) = 0
            // (-7) * 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 23, 5, 3), // x23 = mulhsu(-7, 0) = 0
            // 8. Additional boundary cases
            // 0x00001000 * 0x00001000
            // 0x1000 * 0x1000 = 4096 * 4096 = 16777216 = 0x1000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 24, 8, 8), // x24 = mulhsu(0x1000, 0x1000) = 0
            // (-1) * 0x40000000
            // 0xFFFFFFFF * 0x40000000 = -1 * 1073741824 = -1073741824 = 0xC0000000
            // Upper bits = 0xFFFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 28, 4, 27), // x28 = mulhsu(-1, 0x40000000)
            // 1 * MAX_UINT
            // 1 * 0xFFFFFFFF = 4294967295 = 0xFFFFFFFF. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHSU), 29, 30, 25), // x29 = mulhsu(1, MAX_UINT) = 0
        ]);
        vec![basic_block]
    }

    fn test_k_trace_constrained_instructions(basic_block: Vec<BasicBlock>) {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            MulhMulhsuChip,
            LuiChip,
            SrlChip,
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
    fn test_k_trace_constrained_mulhsu_instructions() {
        let basic_block = setup_basic_mulhsu_block_ir();
        test_k_trace_constrained_instructions(basic_block);
    }

    #[test]
    fn test_k_trace_constrained_mulh_instructions() {
        let basic_block = setup_basic_mulh_block_ir();
        test_k_trace_constrained_instructions(basic_block);
    }
}
