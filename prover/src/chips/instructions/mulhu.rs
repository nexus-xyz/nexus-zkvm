use crate::extensions::ExtensionsConfig;
use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};
use nexus_vm::riscv::BuiltinOpcode;
use stwo_prover::core::fields::m31::BaseField;

pub struct MulhuResult {
    pub p3_prime: [u8; 2],
    pub c3_prime: bool,
    pub p3_prime_prime: [u8; 2],
    pub c3_prime_prime: bool,
    pub _a_l: [u8; 4],
    pub _a_h: [u8; 4],
    pub carry_l: [u8; 3],
    pub carry_h: [u8; 3],
    pub p5: [u8; 2],
    pub c5: bool,
}

pub fn mulh_limb(b: u32, c: u32) -> MulhuResult {
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

    assert!(carry_1_0 < 2, "Carry_1_0 exceeds expected bounds");
    assert!(carry_1_1 < 2, "Carry_1_1 exceeds expected bounds");
    assert!(carry_2_0 < 2, "Carry_2_0 exceeds expected bounds");
    assert!(carry_2_1 < 2, "Carry_2_1 exceeds expected bounds");

    // Return all intermediate and final results for verification and testing
    MulhuResult {
        p3_prime: p3_prime.to_le_bytes(),
        c3_prime: c3_prime == 1,
        p3_prime_prime: p3_prime_prime.to_le_bytes(),
        c3_prime_prime: c3_prime_prime == 1,
        p5: p5.to_le_bytes(),
        c5: c5 == 1,
        _a_l: a_l_bytes,
        _a_h: a_h_bytes,
        carry_l: [carry_0 as u8, carry_1_0 as u8, carry_1_1 as u8],
        carry_h: [carry_2_0 as u8, carry_2_1 as u8, carry_3 as u8],
    }
}

pub struct MulhuChip;

impl MachineChip for MulhuChip {
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
            Some(BuiltinOpcode::MULHU)
        ) {
            return;
        }

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // MUL main constraint need these intermediate values
        let mul_result = mulh_limb(u32::from_le_bytes(value_b), u32::from_le_bytes(value_c));

        // Fill in the intermediate values into traces
        // MUL carry_1 for lower half, in {0, 1, 2, 3}
        traces.fill_columns(row_idx, mul_result.carry_l[1], MulCarry1_0);
        traces.fill_columns(row_idx, mul_result.carry_l[2], MulCarry1_1);

        traces.fill_columns(row_idx, mul_result.carry_h[0], MulCarry2_0);
        traces.fill_columns(row_idx, mul_result.carry_h[1], MulCarry2_1);
        traces.fill_columns(row_idx, mul_result.carry_h[2], MulCarry3);

        // MUL P3', P3'' and P5 in range 0..=2^16 - 1
        traces.fill_columns(row_idx, mul_result.p3_prime, MulP3Prime);
        traces.fill_columns(row_idx, mul_result.p3_prime_prime, MulP3PrimePrime);
        traces.fill_columns(row_idx, mul_result.p5, MulP5);

        // MUL Carry of P3', P3'' and P5 in {0, 1}
        traces.fill_columns(row_idx, mul_result.c3_prime, MulC3Prime);
        traces.fill_columns(row_idx, mul_result.c3_prime_prime, MulC3PrimePrime);
        traces.fill_columns(row_idx, mul_result.c5, MulC5);

        // The output of the multiplication
        traces.fill_columns(
            row_idx,
            vm_step.get_result().expect("MULH must have result"),
            ValueA,
        );
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_mulhu] = trace_eval!(trace_eval, IsMulhu);

        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);

        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let p5 = trace_eval!(trace_eval, MulP5);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);
        let [c5] = trace_eval!(trace_eval, MulC5);

        let z_0 = value_b[0].clone() * value_c[0].clone();
        let z_1 = value_b[1].clone() * value_c[1].clone();
        let z_2 = value_b[2].clone() * value_c[2].clone();
        let z_3 = value_b[3].clone() * value_c[3].clone();

        // (is_mul + is_mulh + is_mulhu + is_mulhsu + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 ′3 + 𝑐′3 ⋅ 2^16 − (|𝑏|0 + |𝑏|3) ⋅ (|𝑐|0 + |𝑐|3) + 𝑧0 + 𝑧3]
        eval.add_constraint(
            is_mulhu.clone()
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
            is_mulhu.clone()
                * (p3_prime_prime[0].clone()
                    + p3_prime_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime_prime.clone() * BaseField::from(1 << 16)
                    - (value_b[1].clone() + value_b[2].clone())
                        * (value_c[1].clone() + value_c[2].clone())
                    + z_1.clone()
                    + z_2.clone()),
        );

        // (is_mulh + is_mulhu + is_mulhsu) ⋅ [𝑃 5 + 𝑐5 ⋅ 2^16 − (|𝑏|2 + |𝑏|3) ⋅ (|𝑐|2 + |𝑐|3) + 𝑧2 + 𝑧3]
        eval.add_constraint(
            is_mulhu.clone()
                * (p5[0].clone()
                    + p5[1].clone() * BaseField::from(1 << 8)
                    + c5.clone() * BaseField::from(1 << 16)
                    - (value_b[2].clone() + value_b[3].clone())
                        * (value_c[2].clone() + value_c[3].clone())
                    + z_2.clone()
                    + z_3.clone()),
        );
        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);
        let [mul_carry_2_0] = trace_eval!(trace_eval, MulCarry2_0);
        let [mul_carry_2_1] = trace_eval!(trace_eval, MulCarry2_1);
        let [mul_carry_3] = trace_eval!(trace_eval, MulCarry3);

        // ((is_mulh + is_mulhu + is_mulhsu) ⋅ [𝑧2 + 𝑃 ′3_ℎ + 𝑃 ″3_ℎ + (𝑏1 + 𝑏3) ⋅ (𝑐1 + 𝑐3) − 𝑧1 − 𝑧3 +
        // (𝑃 5_𝑙 + 𝑐″3 + 𝑐′3) ⋅ 2^8 + carry1 − carry2 ⋅ 2^16 − |𝑎|0 − |𝑎|1 ⋅ 2^8]
        eval.add_constraint(
            is_mulhu.clone()
                * (z_2.clone()
                    + p3_prime[1].clone()
                    + p3_prime_prime[1].clone()
                    + (value_b[1].clone() + value_b[3].clone())
                        * (value_c[1].clone() + value_c[3].clone())
                    - z_1.clone()
                    - z_3.clone()
                    + (p5[0].clone() + c3_prime_prime.clone() + c3_prime.clone())
                        * BaseField::from(1 << 8)
                    + mul_carry_1_0.clone()
                    + mul_carry_1_1.clone() * BaseField::from(1 << 1)
                    - mul_carry_2_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_2_1.clone() * BaseField::from(1 << 17)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhu + is_mulhsu) ⋅(𝑧3 + 𝑃 5ℎ + 𝑐5 ⋅ 2^8 + carry2 − carry3 ⋅ 2^16 − |𝑎|2 − |𝑎|3 ⋅ 2^8)
        eval.add_constraint(
            is_mulhu.clone()
                * (z_3.clone()
                    + p5[1].clone()
                    + c5.clone() * BaseField::from(1 << 8)
                    + mul_carry_2_0
                    + mul_carry_2_1 * BaseField::from(1 << 1)
                    - mul_carry_3 * BaseField::from(1 << 16)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, LuiChip, MulhuChip, ProgramMemCheckChip,
            RangeCheckChip, RegisterMemCheckChip, SrlChip, SubChip,
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
            // Setup registers with various unsigned values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5), // x1 = 5 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 7), // x2 = 7 (small positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 0), // x3 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1), // x4 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 2), // x5 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 6, 0, 0xFFFFF), // x6 = 0xFFFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 6, 0xFFF), // x6 = 0xFFFFFFFF (max u32)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 7, 0, 0x80000), // x7 = 0x80000000 (msb set)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 8, 0, 1),       // x8 = 0x10000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 30), // x9 = 0xFFFFFFFF (max u32, alt)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 9, 9, 16), // x9 = 0x0000FFFF
            // --- MULHU Tests ---
            // Small positive * Small positive (result fits in lower 32 bits)
            // 5 * 7 = 35 = 0x23. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 10, 1, 2), // x10 = mulhu(5, 7) = 0
            // Max u32 * Max u32
            // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001. Upper bits = 0xFFFFFFFE.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 11, 6, 6), // x11 = mulhu(max_u32, max_u32) = 0xFFFFFFFE
            // Max u32 * Small positive
            // 0xFFFFFFFF * 7 = 0x6FFFFFF9. Upper bits = 6.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 12, 6, 2), // x12 = mulhu(max_u32, 7) = 6
            // Small positive * Max u32
            // 5 * 0xFFFFFFFF = 0x4FFFFFFB. Upper bits = 4.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 13, 1, 6), // x13 = mulhu(5, max_u32) = 4
            // Multiplication by zero
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 14, 1, 3), // x14 = mulhu(5, 0) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 15, 6, 3), // x15 = mulhu(max_u32, 0) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 16, 3, 3), // x16 = mulhu(0, 0) = 0
            // Multiplication by one
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 17, 6, 4), // x17 = mulhu(max_u32, 1) = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 18, 1, 4), // x18 = mulhu(5, 1) = 0
            // MSB set * 2 (causes carry into upper half)
            // 0x80000000 * 2 = 0x100000000. Upper bits = 1.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 19, 7, 5), // x19 = mulhu(0x80000000, 2) = 1
            // MSB set * MSB set
            // 0x80000000 * 0x80000000 = 0x4000000000000000. Upper bits = 0x40000000.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 20, 7, 7), // x20 = mulhu(0x80000000, 0x80000000) = 0x40000000
            // --- Additional Edge Cases ---
            // 0x10000 * 0x10000 (boundary case for lower/upper half)
            // 0x10000 * 0x10000 = 0x100000000. Upper bits = 1.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 21, 8, 8), // x21 = mulhu(0x10000, 0x10000) = 1
            // 0x0000FFFF * 0x0000FFFF (max 16-bit * max 16-bit)
            // 0xFFFF * 0xFFFF = 0xFFFE0001. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 22, 9, 9), // x22 = mulhu(0xFFFF, 0xFFFF) = 0
            // 0x10000 * 0xFFFF (boundary * near boundary)
            // 0x10000 * 0xFFFF = 0xFFFF0000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 23, 8, 9), // x23 = mulhu(0x10000, 0xFFFF) = 0
            // MSB set * 1
            // 0x80000000 * 1 = 0x80000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 24, 7, 4), // x24 = mulhu(0x80000000, 1) = 0
            // 1 * MSB set
            // 1 * 0x80000000 = 0x80000000. Upper bits = 0.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 25, 4, 7), // x25 = mulhu(1, 0x80000000) = 0
            // Max u32 * Max u32 (using alternative register for max u32)
            // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001. Upper bits = 0xFFFFFFFE.
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 26, 0, 30), // x26 = 0xFFFFFFFF
            Instruction::new_ir(Opcode::from(BuiltinOpcode::MULHU), 27, 6, 26), // x27 = mulhu(max_u32, max_u32) = 0xFFFFFFFE
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_mulhu_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            MulhuChip,
            LuiChip,
            SrlChip,
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
