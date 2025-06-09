use crate::extensions::ExtensionsConfig;
use nexus_vm::riscv::BuiltinOpcode;
use stwo_prover::core::fields::m31::BaseField;

use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};

pub struct MulResult {
    pub p1: [u8; 2],
    pub c1: bool,
    pub p3_prime: [u8; 2],
    pub c3_prime: bool,
    pub p3_prime_prime: [u8; 2],
    pub c3_prime_prime: bool,
    pub _a_l: [u8; 4],
    pub _a_h: [u8; 4],
    pub carry_l: [u8; 3],
    pub _carry_h: [u8; 3],
    pub _p5: [u8; 2],
    pub _c5: bool,
}

pub fn mul_limb(b: u32, c: u32) -> MulResult {
    // Convert inputs to limbs (4 bytes each)
    let b_limbs = b.to_le_bytes();
    let c_limbs = c.to_le_bytes();

    // Calculate the full 64-bit product using built-in operation
    // This serves as our reference result for verification
    let product = (b as u64) * (c as u64);
    let a_l = product as u32;
    let a_h = (product >> 32) as u32;
    let a_l_bytes = a_l.to_le_bytes();
    let a_h_bytes = a_h.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 1: Compute the 8x8 bit multiplications for each byte pair
    //--------------------------------------------------------------
    // Calculate the individual limb products (each byte multiplied)
    let z0_prod = (c_limbs[0] as u16) * (b_limbs[0] as u16);
    let z0_l = z0_prod as u8;
    let z0_h = (z0_prod >> 8) as u8;

    let z1_prod = (c_limbs[1] as u16) * (b_limbs[1] as u16);
    let z1_l = z1_prod as u8;
    let z1_h = (z1_prod >> 8) as u8;

    let z2_prod = (c_limbs[2] as u16) * (b_limbs[2] as u16);
    let z2_l = z2_prod as u8;
    let z2_h = (z2_prod >> 8) as u8;

    let z3_prod = (c_limbs[3] as u16) * (b_limbs[3] as u16);
    let z3_l = z3_prod as u8;
    let z3_h = (z3_prod >> 8) as u8;

    // Combine low and high parts of each limb product to form 16-bit values
    let z0 = (z0_l as u16).wrapping_add((z0_h as u16) << 8);
    let z1 = (z1_l as u16).wrapping_add((z1_h as u16) << 8);
    let z2 = (z2_l as u16).wrapping_add((z2_h as u16) << 8);
    let z3 = (z3_l as u16).wrapping_add((z3_h as u16) << 8);

    // Convert limbs to u32 for easier calculations with larger intermediate values
    let c_limbs = c_limbs.map(|x| x as u32);
    let b_limbs = b_limbs.map(|x| x as u32);

    //--------------------------------------------------------------
    // STEP 2: Karatsuba multiplication - compute intermediate products
    //--------------------------------------------------------------
    // p1 = (c0+c1)(b0+b1) - z0 - z1
    let p1 = (c_limbs[0].wrapping_add(c_limbs[1]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[1]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z1 as u32);
    let (p1, c1) = (p1 as u16, (p1 >> 16));

    // p2_prime = (c0+c2)(b0+b2) - z0 - z2
    let p2_prime = (c_limbs[0].wrapping_add(c_limbs[2]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[2]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z2 as u32);

    // p3_prime = (c0+c3)(b0+b3) - z0 - z3
    let p3_prime = (c_limbs[0].wrapping_add(c_limbs[3]))
        .wrapping_mul(b_limbs[0].wrapping_add(b_limbs[3]))
        .wrapping_sub(z0 as u32)
        .wrapping_sub(z3 as u32);
    let (p3_prime, c3_prime) = (p3_prime as u16, p3_prime >> 16);

    // p3_prime_prime = (c1+c2)(b1+b2) - z1 - z2
    let p3_prime_prime = (c_limbs[1].wrapping_add(c_limbs[2]))
        .wrapping_mul(b_limbs[1].wrapping_add(b_limbs[2]))
        .wrapping_sub(z1 as u32)
        .wrapping_sub(z2 as u32);
    let (p3_prime_prime, c3_prime_prime) = (p3_prime_prime as u16, p3_prime_prime >> 16);

    // Verify that our carries stay within expected bounds
    // These assertions help catch potential overflow issues
    assert!(c1 < 2, "Carry c1 exceeds expected bounds");
    assert!(c3_prime < 2, "Carry c3_prime exceeds expected bounds");
    assert!(
        c3_prime_prime < 2,
        "Carry c3_prime_prime exceeds expected bounds"
    );

    // Split intermediate products into high and low bytes for further calculations
    let (p1_h, p1_l) = (p1 >> 8, p1 & 0xFF);

    // Get low bytes from intermediate products
    let p3_prime_l = p3_prime & 0xFF;
    let p3_prime_h = (p3_prime >> 8) & 0xFF; // Extract high byte properly

    let p3_prime_prime_l = p3_prime_prime & 0xFF;
    let p3_prime_prime_h = (p3_prime_prime >> 8) & 0xFF; // Extract high byte properly

    //--------------------------------------------------------------
    // STEP 3: Form the lower 32 bits of the final result
    //--------------------------------------------------------------
    // First two bytes of the result (bytes 0-1)
    // Calculate z0 + (p1_l << 8)
    let temp_sum_0 = (z0 as u32) + ((p1_l << 8) as u32);
    let a01 = temp_sum_0 as u16;
    let carry_0 = (temp_sum_0 >> 16) as u16; // Carry value (0 or 1)

    // Next two bytes of the result (bytes 2-3)
    let a23 = (z1 as u32)
        .wrapping_add(p1_h as u32)
        .wrapping_add(p2_prime)
        .wrapping_add(carry_0 as u32)
        .wrapping_add(((p3_prime_l + p3_prime_prime_l + c1 as u16) as u32) << 8);
    let (a23, carry_1) = (a23 as u16, (a23 >> 16));

    // Verify our calculations match the built-in multiplication
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {}", carry_1);
    assert_eq!(
        a01.to_le_bytes(),
        [a_l_bytes[0], a_l_bytes[1]],
        "Low bytes (0-1) mismatch"
    );
    assert_eq!(
        a23.to_le_bytes(),
        [a_l_bytes[2], a_l_bytes[3]],
        "Low bytes (2-3) mismatch"
    );

    //--------------------------------------------------------------
    // STEP 4: Form the upper 32 bits of the final result
    //--------------------------------------------------------------
    // Calculate remaining Karatsuba products needed for high bytes
    let p4_prime = b_limbs[1]
        .wrapping_add(b_limbs[3])
        .wrapping_mul(c_limbs[1].wrapping_add(c_limbs[3]))
        .wrapping_sub(z1 as u32)
        .wrapping_sub(z3 as u32);

    let p5 = b_limbs[2]
        .wrapping_add(b_limbs[3])
        .wrapping_mul(c_limbs[2].wrapping_add(c_limbs[3]))
        .wrapping_sub(z2 as u32)
        .wrapping_sub(z3 as u32);

    let (p5, c5) = (p5 as u16, p5 >> 16);
    let (p5_h, p5_l) = (p5 >> 8, p5 & 0xFF);

    assert!(c5 < 2, "Carry c5 exceeds expected bounds");

    // Bytes 4-5 of the final result
    let a45 = (z2 as u32)
        .wrapping_add(p4_prime)
        .wrapping_add(p3_prime_h as u32)
        .wrapping_add(p3_prime_prime_h as u32)
        .wrapping_add((p5_l as u32) << 8)
        .wrapping_add(carry_1)
        .wrapping_add((c3_prime) << 8)
        .wrapping_add((c3_prime_prime) << 8);
    let (a45, carry_2) = (a45 as u16, (a45 >> 16));

    assert!(carry_2 < 4, "Carry_2 exceeds expected bounds {}", carry_2);

    // Bytes 6-7 of the final result
    let a67 = (z3 as u32)
        .wrapping_add(p5_h as u32)
        .wrapping_add((c5) << 8)
        .wrapping_add(carry_2);
    let (a67, carry_3) = (a67 as u16, (a67 >> 16));

    assert!(carry_3 < 2, "Carry_3 exceeds expected bounds");

    // Verify our high bytes match the built-in multiplication
    assert_eq!(
        a45.to_le_bytes(),
        [a_h_bytes[0], a_h_bytes[1]],
        "High bytes (4-5) mismatch"
    );
    assert_eq!(
        a67.to_le_bytes(),
        [a_h_bytes[2], a_h_bytes[3]],
        "High bytes (6-7) mismatch"
    );
    let (carry_1_0, carry_1_1) = (carry_1 & 0x1, (carry_1 >> 1) & 0x1);
    let (carry_2_0, carry_2_1) = (carry_2 & 0x1, (carry_2 >> 1) & 0x1);

    // Return all intermediate and final results for verification and testing
    MulResult {
        p1: p1.to_le_bytes(),
        c1: c1 == 1,
        p3_prime: p3_prime.to_le_bytes(),
        c3_prime: c3_prime == 1,
        p3_prime_prime: p3_prime_prime.to_le_bytes(),
        c3_prime_prime: c3_prime_prime == 1,
        _p5: p5.to_le_bytes(),
        _c5: c5 == 1,
        _a_l: a_l_bytes,
        _a_h: a_h_bytes,
        carry_l: [carry_0 as u8, carry_1_0 as u8, carry_1_1 as u8],
        _carry_h: [carry_2_0 as u8, carry_2_1 as u8, carry_3 as u8],
    }
}

pub struct MulChip;

impl MachineChip for MulChip {
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
            Some(BuiltinOpcode::MUL)
        ) {
            return;
        }

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // MUL main constraint need these intermediate values
        let mul_result = mul_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));

        // Fill in the intermediate values into traces
        // MUL carry_0 for lower half, in {0, 1}
        traces.fill_columns(row_idx, mul_result.carry_l[0], MulCarry0);
        // MUL carry_1 for lower half, in {0, 1, 2, 3}
        traces.fill_columns(row_idx, mul_result.carry_l[1], MulCarry1_0);
        traces.fill_columns(row_idx, mul_result.carry_l[2], MulCarry1_1);

        // MUL P1, P3' and P3'' in range [0, 2^16 - 1]
        traces.fill_columns(row_idx, mul_result.p1, MulP1);
        traces.fill_columns(row_idx, mul_result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, mul_result.p3_prime_prime, MulP3PrimePrime);

        // MUL Carry of P1, P3' and P3'' in {0, 1}
        traces.fill_columns(row_idx, mul_result.c1, MulC1);
        traces.fill_columns(row_idx, mul_result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, mul_result.c3_prime_prime, MulC3PrimePrime);

        // The output of the multiplication
        traces.fill_columns(
            row_idx,
            vm_step.get_result().expect("MUL must have result"),
            ValueA,
        );
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_mul] = trace_eval!(trace_eval, IsMul);
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);

        let p1 = trace_eval!(trace_eval, MulP1);
        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let [c1] = trace_eval!(trace_eval, MulC1);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);

        let z_0 = value_b[0].clone() * value_c[0].clone();
        let z_1 = value_b[1].clone() * value_c[1].clone();
        let z_2 = value_b[2].clone() * value_c[2].clone();
        let z_3 = value_b[3].clone() * value_c[3].clone();

        // (is_mul + is_mulh + is_mulhu + is_mulhsu + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 ′3 + 𝑐′3 ⋅ 2^16 − (|𝑏|0 + |𝑏|3) ⋅ (|𝑐|0 + |𝑐|3) + 𝑧0 + 𝑧3]
        eval.add_constraint(
            is_mul.clone()
                * (p3_prime[0].clone()
                    + p3_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime.clone() * BaseField::from(1 << 16)
                    - (value_b[0].clone() + value_b[3].clone())
                        * (value_c[0].clone() + value_c[3].clone())
                    + z_0.clone()
                    + z_3.clone()),
        );

        // (is_mul + is_mulh + is_mulhu + is_mulhsu + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 ″3 + 𝑐″3 ⋅ 2^16 − (|𝑏|1 + |𝑏|2) ⋅ (|𝑐|1 + |𝑐|2) + 𝑧1 + 𝑧2]
        eval.add_constraint(
            is_mul.clone()
                * (p3_prime_prime[0].clone()
                    + p3_prime_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime_prime.clone() * BaseField::from(1 << 16)
                    - (value_b[1].clone() + value_b[2].clone())
                        * (value_c[1].clone() + value_c[2].clone())
                    + z_1.clone()
                    + z_2.clone()),
        );

        // (is_mul + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 1 + 𝑐1 ⋅ 2^16 − (|𝑏|0 + |𝑏|1) ⋅ (|𝑐|0 + |𝑐|1) + 𝑧0 + 𝑧1]
        eval.add_constraint(
            is_mul.clone()
                * (p1[0].clone()
                    + p1[1].clone() * BaseField::from(1 << 8)
                    + c1.clone() * BaseField::from(1 << 16)
                    - (value_b[0].clone() + value_b[1].clone())
                        * (value_c[0].clone() + value_c[1].clone())
                    + z_0.clone()
                    + z_1.clone()),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);

        // is_mul ⋅ (𝑧0 + 𝑃1_𝑙 ⋅ 2^8 − carry0 ⋅ 2^16 − |𝑎|0 − |𝑎|1 ⋅ 2^8)
        eval.add_constraint(
            is_mul.clone()
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );

        // is_mul ⋅
        // [𝑧1 + 𝑃 1ℎ + (𝑏0 + 𝑏2) ⋅ (𝑐0 + 𝑐2) − 𝑧0 − 𝑧2 +(𝑃 ′3𝑙 + 𝑃 ″3𝑙 + 𝑐1) ⋅ 2^8 + carry0 − carry1 ⋅ 2^16 − |𝑎|2 − |𝑎|3 ⋅ 2^8]
        eval.add_constraint(
            is_mul.clone()
                * (z_1.clone()
                    + p1[1].clone()
                    + (value_b[0].clone() + value_b[2].clone())
                        * (value_c[0].clone() + value_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + mul_carry_0.clone()
                    - mul_carry_1_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_1_1.clone() * BaseField::from(1 << 17)
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, LuiChip, MulChip, ProgramMemCheckChip,
            RangeCheckChip, RegisterMemCheckChip, SubChip,
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

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Test multiplication with various inputs
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 3, 2, 1),  // x3 = x1 * x2 = 35
            // Test multiplication with negative values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 3), // x4 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4),  // x4 = -3 (0xFFFFFFFD)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 5, 4, 2), // x5 = x4 * x2 = -21 (0xFFFFFFEB)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 6, 1, 4), // x6 = x1 * x4 = -15 (0xFFFFFFF1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 7, 4, 4), // x7 = x4 * x4 = 9 (negative * negative = positive)
            // Test multiplication with zero
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 9, 8, 1),  // x9 = x8 * x1 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 10, 4, 8), // x10 = x4 * x8 = 0
            // Test multiplication with larger values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 100), // x11 = 100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 12, 0, 200), // x12 = 200
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 13, 11, 12), // x13 = x11 * x12 = 20000
            // Test overflow cases (positive * positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 65535), // x14 = 65535 (0xFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 15, 14, 14), // x15 = x14 * x14 = 0xFFFE0001 (-131071)
            // --- Edge Cases ---
            // Load constants: 0x7FFFFFFF (max_pos), 0x80000000 (min_neg), -1 (max_neg), 1 (min_pos)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 16, 0, 0x7FFFF), // x16 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 16, 0xFFF), // x16 = 0x7FFFFFFF (max_pos)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 17, 0, 0x80000), // x17 = 0x80000000 (min_neg)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 18, 0, 1),      // x18 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 18, 0, 18), // x18 = -1 (0xFFFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 1), // x19 = 1
            // Test max_pos * max_pos
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 20, 16, 16), // x20 = 0x7FFFFFFF * 0x7FFFFFFF = 0x00000001
            // Test min_neg * min_neg
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 22, 17, 17), // x22 = 0x80000000 * 0x80000000 = 0x00000000
            // Test max_pos * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 23, 16, 19), // x23 = 0x7FFFFFFF * 1 = 0x7FFFFFFF
            // Test -1 * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 27, 18, 18), // x27 = -1 * -1 = 1
            // Test -1 * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 28, 18, 19), // x28 = -1 * 1 = -1
            // Test multiplication resulting in 0x80000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 29, 0, 0x40000), // x29 = 0x40000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 2),      // x30 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 31, 29, 30), // x31 = 0x40000000 * 2 = 0x7FFFFFFF
            //    Test max_pos * min_neg
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 21, 16, 17), // x21 = 0x7FFFFFFF * 0x80000000 = 0x80000000
            //    Test min_neg * 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 24, 17, 19), // x24 = 0x80000000 * 1 = 0x80000000
            //    Test max_pos * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 25, 16, 18), // x25 = 0x7FFFFFFF * -1 = 0x80000001
            //    Test min_neg * -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MUL), 26, 17, 18), // x26 = 0x80000000 * -1 = 0x80000000
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_mul_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            MulChip,
            LuiChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
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
}
