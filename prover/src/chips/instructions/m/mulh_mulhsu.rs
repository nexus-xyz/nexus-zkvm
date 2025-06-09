use crate::extensions::ExtensionsConfig;
use crate::{
    column::Column::{self, *},
    trace::eval::trace_eval,
    traits::MachineChip,
};
use nexus_vm::riscv::BuiltinOpcode;
use num_traits::One;
use stwo_prover::core::fields::m31::BaseField;

#[derive(Debug, Clone, Copy)]
pub struct AbsResult {
    pub abs_limbs: [u8; 4],
    pub carry: [bool; 2],
    pub sgn: bool,
}

/// Compute the absolute value of a 32-bit integer represented as 4 8-bit limbs
///
/// This function implements absolute value computation using limb-by-limb operations:
/// 1. For negative numbers: We negate each limb (two's complement) and add 1
/// 2. For non-negative numbers: We return the original value
///
/// The two's complement negation is done by:
/// - Inverting each bit (complementing)
/// - Adding 1 to the result
///
/// Returns the absolute value result as limbs and carry flags
pub fn abs_limb(n: u32) -> AbsResult {
    //--------------------------------------------------------------
    // STEP 1: Determine the sign of input and prepare limbs
    //--------------------------------------------------------------
    // Extract the sign bit (1 if negative, 0 if positive)
    let sgn_n = (n >> 31) & 1;
    assert!(sgn_n < 2, "Sign bit must be 0 or 1");

    // Convert input to individual bytes (limbs)
    let n_limbs = n.to_le_bytes().map(|x| x as u32);
    let mut limbs = n.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 2: Negate using two's complement (for negative numbers)
    //--------------------------------------------------------------
    // First complement: invert all bits
    for l in &mut limbs {
        *l = u8::MAX - *l;
    }

    // Second complement: add 1 and propagate carry
    let mut carry = [false; 4];

    // Add 1 to the least significant limb and propagate carry
    (limbs[0], carry[0]) = limbs[0].overflowing_add(1);
    (limbs[1], carry[1]) = limbs[1].overflowing_add(carry[0] as u8);
    (limbs[2], carry[2]) = limbs[2].overflowing_add(carry[1] as u8);
    (limbs[3], carry[3]) = limbs[3].overflowing_add(carry[2] as u8);

    //--------------------------------------------------------------
    // STEP 3: Verify correctness using mathematical constraints
    //--------------------------------------------------------------
    // Convert boolean carries to u32 and limbs to u32 for verification
    let carry_u32 = carry.map(|x| x as u32);
    let limbs_u32 = limbs.map(|x| x as u32);

    // Verify lower 16 bits correctness
    let unsigned_lower: u32 = limbs_u32[0] + (limbs_u32[1] << 8);
    let signed_lower: u32 = (1u32 << 16)
        .wrapping_sub(n_limbs[0])
        .wrapping_sub(n_limbs[1] << 8)
        .wrapping_sub((carry_u32[1]) << 16);

    // This equation verifies correct two's complement calculation for lower 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_lower + sgn_n * signed_lower,
        unsigned_lower,
        "Lower 16 bits verification failed"
    );

    // Verify upper 16 bits correctness
    let unsigned_upper: u32 = limbs_u32[2] + (limbs_u32[3] << 8);
    let signed_upper: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[2])
        .wrapping_sub(n_limbs[3] << 8)
        .wrapping_add(carry_u32[1])
        .wrapping_sub((carry_u32[3]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper + sgn_n * signed_upper,
        unsigned_upper,
        "Upper 16 bits verification failed"
    );

    //--------------------------------------------------------------
    // STEP 4: Return the absolute value
    //--------------------------------------------------------------
    // Early return for non-negative numbers
    if sgn_n == 0 {
        AbsResult {
            sgn: sgn_n == 1,
            abs_limbs: n.to_le_bytes(),
            carry: [false, false],
        }
    } else {
        // For negative input, return the computed absolute value
        AbsResult {
            sgn: sgn_n == 1,
            abs_limbs: limbs,
            carry: [carry[1], carry[3]], // Store only the important carry bits
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AbsResult64 {
    pub _abs_limbs: [u8; 8],
    pub carry_low: [bool; 2],
    pub carry_high: [bool; 2],
    pub sgn: bool,
}

/// Compute the absolute value of a 64-bit integer represented as 8 8-bit limbs
///
/// This function implements absolute value computation using limb-by-limb operations:
/// 1. For negative numbers: We negate each limb (two's complement) and add 1
/// 2. For non-negative numbers: We return the original value
///
/// The two's complement negation is done by:
/// - Inverting each bit (complementing)
/// - Adding 1 to the result
///
/// Returns the absolute value result as limbs and carry flags
pub fn abs64_limb(low: u32, high: u32) -> AbsResult64 {
    //--------------------------------------------------------------
    // STEP 1: Determine the sign of input and prepare limbs
    //--------------------------------------------------------------
    // Extract the sign bit (1 if negative, 0 if positive)
    let n = ((high as u64) << 32) | low as u64;
    let sgn_n = (high >> 31) & 1;
    assert!(sgn_n < 2, "Sign bit must be 0 or 1");

    // Convert input to individual bytes (limbs)
    let n_limbs = n.to_le_bytes().map(|x| x as u32);
    let mut limbs = n.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 2: Negate using two's complement (for negative numbers)
    //--------------------------------------------------------------
    // First complement: invert all bits
    for l in &mut limbs {
        *l = u8::MAX - *l;
    }

    // Second complement: add 1 and propagate carry
    let mut carry = [false; 8];

    // Add 1 to the least significant limb and propagate carry
    (limbs[0], carry[0]) = limbs[0].overflowing_add(1);
    (limbs[1], carry[1]) = limbs[1].overflowing_add(carry[0] as u8);
    (limbs[2], carry[2]) = limbs[2].overflowing_add(carry[1] as u8);
    (limbs[3], carry[3]) = limbs[3].overflowing_add(carry[2] as u8);
    (limbs[4], carry[4]) = limbs[4].overflowing_add(carry[3] as u8);
    (limbs[5], carry[5]) = limbs[5].overflowing_add(carry[4] as u8);
    (limbs[6], carry[6]) = limbs[6].overflowing_add(carry[5] as u8);
    (limbs[7], carry[7]) = limbs[7].overflowing_add(carry[6] as u8);

    //--------------------------------------------------------------
    // STEP 3: Verify correctness using mathematical constraints
    //--------------------------------------------------------------
    // Convert boolean carries to u32 and limbs to u32 for verification
    let carry_u32 = carry.map(|x| x as u32);
    let limbs_u32 = limbs.map(|x| x as u32);

    // Verify lower 32 bits correctness
    // Verify bits 0->15 correctness
    let unsigned_lower_0_15: u32 = limbs_u32[0] + (limbs_u32[1] << 8);
    let signed_lower_0_15: u32 = (1u32 << 16)
        .wrapping_sub(n_limbs[0])
        .wrapping_sub(n_limbs[1] << 8)
        .wrapping_sub((carry_u32[1]) << 16);

    // This equation verifies correct two's complement calculation for lower 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_lower_0_15 + sgn_n * signed_lower_0_15,
        unsigned_lower_0_15,
        "Lower 16 bits verification failed"
    );

    // Verify bits 16->31 correctness
    let unsigned_upper_16_31: u32 = limbs_u32[2] + (limbs_u32[3] << 8);
    let signed_upper_16_31: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[2])
        .wrapping_sub(n_limbs[3] << 8)
        .wrapping_add(carry_u32[1])
        .wrapping_sub((carry_u32[3]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_16_31 + sgn_n * signed_upper_16_31,
        unsigned_upper_16_31,
        "Upper 16 bits verification failed"
    );

    // Verify upper 32 bits correctness
    // Verify bits 32->47 correctness
    let unsigned_upper_32_47: u32 = limbs_u32[4] + (limbs_u32[5] << 8);
    let signed_upper_32_47: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[4])
        .wrapping_sub(n_limbs[5] << 8)
        .wrapping_add(carry_u32[3])
        .wrapping_sub((carry_u32[5]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_32_47 + sgn_n * signed_upper_32_47,
        unsigned_upper_32_47,
        "Upper 16 bits verification failed"
    );

    // Verify bits 48->63 correctness
    let unsigned_upper_48_63: u32 = limbs_u32[6] + (limbs_u32[7] << 8);
    let signed_upper_48_63: u32 = (1u32 << 16)
        .wrapping_sub(1)
        .wrapping_sub(n_limbs[6])
        .wrapping_sub(n_limbs[7] << 8)
        .wrapping_add(carry_u32[5])
        .wrapping_sub((carry_u32[7]) << 16);

    // This equation verifies correct two's complement calculation for upper 16 bits
    assert_eq!(
        (1 - sgn_n) * unsigned_upper_48_63 + sgn_n * signed_upper_48_63,
        unsigned_upper_48_63,
        "Upper 16 bits verification failed"
    );

    //--------------------------------------------------------------
    // STEP 4: Return the absolute value
    //--------------------------------------------------------------
    // Early return for non-negative numbers
    if sgn_n == 0 {
        AbsResult64 {
            sgn: sgn_n == 1,
            _abs_limbs: n.to_le_bytes(),
            carry_low: [false, false],  // No carry for non-negative numbers
            carry_high: [false, false], // No carry for non-negative numbers
        }
    } else {
        // For negative input, return the computed absolute value
        AbsResult64 {
            sgn: sgn_n == 1,
            _abs_limbs: limbs,
            carry_low: [carry[1], carry[3]], // Store only the important carry bits
            carry_high: [carry[5], carry[7]], // Store only the important carry bits
        }
    }
}

pub struct MullResult {
    pub p1: [u8; 2],
    pub c1: bool,
    pub p3_prime: [u8; 2],
    pub c3_prime: bool,
    pub p3_prime_prime: [u8; 2],
    pub c3_prime_prime: bool,
    pub a_l: [u8; 4],
    pub a_h: [u8; 4],
    pub carry_l: [u8; 2],
    pub carry_h: [u8; 2],
    pub p5: [u8; 2],
    pub c5: bool,
}

pub fn mul_limb(b: u32, c: u32) -> MullResult {
    // Convert inputs to limbs (4 bytes each)
    let b_limbs = b.to_le_bytes();
    let c_limbs = c.to_le_bytes();

    // Calculate the full 64-bit product using built-in operation
    // This serves as our reference result for verification
    let (a_l, a_h) = b.widening_mul(c);
    let a_l_bytes = a_l.to_le_bytes();
    let a_h_bytes = a_h.to_le_bytes();

    //--------------------------------------------------------------
    // STEP 1: Compute the 8x8 bit multiplications for each byte pair
    //--------------------------------------------------------------
    // Calculate the individual limb products (each byte multiplied)
    let (z0_l, z0_h) = c_limbs[0].widening_mul(b_limbs[0]);
    let (z1_l, z1_h) = c_limbs[1].widening_mul(b_limbs[1]);
    let (z2_l, z2_h) = c_limbs[2].widening_mul(b_limbs[2]);
    let (z3_l, z3_h) = c_limbs[3].widening_mul(b_limbs[3]);

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
    let (a01, carry_0) = z0.carrying_add(p1_l << 8, false);

    // Next two bytes of the result (bytes 2-3)
    let a23 = (z1 as u32)
        .wrapping_add(p1_h as u32)
        .wrapping_add(p2_prime)
        .wrapping_add(carry_0 as u32)
        .wrapping_add(((p3_prime_l + p3_prime_prime_l + c1 as u16) as u32) << 8);
    let (a23, carry_1) = (a23 as u16, (a23 >> 16));

    // Verify our calculations match the built-in multiplication
    assert!(carry_1 < 4, "Carry_1 exceeds expected bounds {carry_1}");
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

    assert!(carry_2 < 4, "Carry_2 exceeds expected bounds {carry_2}");

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

    // Return all intermediate and final results for verification and testing
    MullResult {
        p1: p1.to_le_bytes(),
        c1: c1 == 1,
        p3_prime: p3_prime.to_le_bytes(),
        c3_prime: c3_prime == 1,
        p3_prime_prime: p3_prime_prime.to_le_bytes(),
        c3_prime_prime: c3_prime_prime == 1,
        p5: p5.to_le_bytes(),
        c5: c5 == 1,
        a_l: a_l_bytes,
        a_h: a_h_bytes,
        carry_l: [carry_0 as u8, carry_1 as u8],
        carry_h: [carry_2 as u8, carry_3 as u8],
    }
}

pub struct MulhMulhsuChip;

fn constraint_gadget_abs32<E: stwo_prover::constraint_framework::EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn: E::F,
    value: [E::F; 4],
    abs_value: [E::F; 4],
    abs_value_borrow: [E::F; 2],
) {
    eval.add_constraint(
        selector.clone()
            * ((E::F::one() - sgn.clone())
                * (value[0].clone() + value[1].clone() * BaseField::from(1 << 8))
                + sgn.clone()
                    * (E::F::from(BaseField::from(1 << 16))
                        - value[0].clone()
                        - value[1].clone() * BaseField::from(1 << 8)
                        - abs_value_borrow[0].clone() * BaseField::from(1 << 16))
                - abs_value[0].clone()
                - abs_value[1].clone() * BaseField::from(1 << 8)),
    );

    eval.add_constraint(
        selector.clone()
            * ((E::F::one() - sgn.clone())
                * (value[2].clone() + value[3].clone() * BaseField::from(1 << 8))
                + sgn.clone()
                    * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                        - value[2].clone()
                        - value[3].clone() * BaseField::from(1 << 8)
                        - abs_value_borrow[1].clone() * BaseField::from(1 << 16)
                        + abs_value_borrow[0].clone())
                - abs_value[2].clone()
                - abs_value[3].clone() * BaseField::from(1 << 8)),
    );
}

fn constraint_gadget_abs64<E: stwo_prover::constraint_framework::EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn: E::F,
    value_low: [E::F; 4],
    value_high: [E::F; 4],
    abs_value_low: [E::F; 4],
    abs_value_high: [E::F; 4],
    abs_value_low_borrow: [E::F; 2],
    abs_value_high_borrow: [E::F; 2],
) {
    constraint_gadget_abs32(
        eval,
        selector.clone(),
        sgn.clone(),
        value_low,
        abs_value_low,
        abs_value_low_borrow.clone(),
    );

    eval.add_constraint(
        selector.clone()
            * ((E::F::one() - sgn.clone())
                * (value_high[0].clone() + value_high[1].clone() * BaseField::from(1 << 8))
                + sgn.clone()
                    * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                        - value_high[0].clone()
                        - value_high[1].clone() * BaseField::from(1 << 8)
                        - abs_value_high_borrow[0].clone() * BaseField::from(1 << 16)
                        + abs_value_low_borrow[1].clone())
                - abs_value_high[0].clone()
                - abs_value_high[1].clone() * BaseField::from(1 << 8)),
    );

    eval.add_constraint(
        selector.clone()
            * ((E::F::one() - sgn.clone())
                * (value_high[2].clone() + value_high[3].clone() * BaseField::from(1 << 8))
                + sgn.clone()
                    * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                        - value_high[2].clone()
                        - value_high[3].clone() * BaseField::from(1 << 8)
                        - abs_value_high_borrow[1].clone() * BaseField::from(1 << 16)
                        + abs_value_high_borrow[0].clone())
                - abs_value_high[2].clone()
                - abs_value_high[3].clone() * BaseField::from(1 << 8)),
    );
}
fn constraint_gadget_is_zero<E: stwo_prover::constraint_framework::EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    is_zero: E::F,
    value: [E::F; 4],
) {
    eval.add_constraint(
        selector.clone()
            * is_zero.clone()
            * (value[0].clone() + value[1].clone() + value[2].clone() + value[3].clone()),
    );
}

fn constraint_gadget_sign_2_to_1<E: stwo_prover::constraint_framework::EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn_out: E::F,
    is_out_zero: E::F,
    sgn_in: [E::F; 2],
) {
    eval.add_constraint(
        selector.clone()
            * (sgn_out.clone()
                - (E::F::one() - is_out_zero.clone())
                    * (sgn_in[0].clone() + sgn_in[1].clone()
                        - sgn_in[0].clone()
                            * sgn_in[1].clone()
                            * BaseField::from_u32_unchecked(2))),
    );
}

fn constraint_gadget_sign_1_to_1<E: stwo_prover::constraint_framework::EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn_out: E::F,
    is_out_zero: E::F,
    sgn_in: E::F,
) {
    eval.add_constraint(
        selector.clone() * (sgn_out.clone() - (E::F::one() - is_out_zero.clone()) * sgn_in.clone()),
    );
}

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

        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        // Commit the absolute value and carry of the operand B to the trace
        let abs_value_b = abs_limb(u32::from_le_bytes(value_b));
        traces.fill_columns(row_idx, abs_value_b.abs_limbs, ValueBAbs);
        traces.fill_columns(row_idx, abs_value_b.carry, ValueBAbsBorrow);
        traces.fill_columns(row_idx, abs_value_b.sgn, SgnB);

        let abs_value_c = abs_limb(u32::from_le_bytes(value_c));
        traces.fill_columns(row_idx, abs_value_c.abs_limbs, ValueCAbs);
        traces.fill_columns(row_idx, abs_value_c.carry, ValueCAbsBorrow);
        traces.fill_columns(row_idx, abs_value_c.sgn, SgnC);

        let result = mul_limb(
            u32::from_le_bytes(abs_value_b.abs_limbs),
            u32::from_le_bytes(abs_value_c.abs_limbs),
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
        traces.fill_columns(row_idx, result.carry_l[1] & 1, MulCarry1_0);
        traces.fill_columns(row_idx, result.carry_l[1] >> 1, MulCarry1_1);
        traces.fill_columns(row_idx, result.carry_h[0] & 1, MulCarry2_0);
        traces.fill_columns(row_idx, result.carry_h[0] >> 1, MulCarry2_1);
        traces.fill_columns(row_idx, result.carry_h[1], MulCarry3);

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
        constraint_gadget_abs32(
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
        constraint_gadget_abs32(
            eval,
            is_mulh.clone(),
            sgn_c.clone(),
            value_c,
            abs_value_c.clone(),
            abs_value_c_borrow.clone(),
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

        // (is_mulh + is_mulhsu) ⋅ [P1_l + P1_h⋅2^8 + c1⋅2^16 - (|b|0 + |b|1)⋅(|c|0 + |c|1) + z0 + z1]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (p1[0].clone()
                    + p1[1].clone() * BaseField::from(1 << 8)
                    + c1.clone() * BaseField::from(1 << 16)
                    - (abs_value_b[0].clone() + abs_value_b[1].clone())
                        * (abs_value_c[0].clone() + abs_value_c[1].clone())
                    + z_0.clone()
                    + z_1.clone()),
        );

        // (is_mulh + is_mulhsu) ⋅ [P'3_l + P'3_h⋅2^8 + c'3⋅2^16 - (|b|0 + |b|3)⋅(|c|0 + |c|3) + z0 + z3]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (p3_prime[0].clone()
                    + p3_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime.clone() * BaseField::from(1 << 16)
                    - (abs_value_b[0].clone() + abs_value_b[3].clone())
                        * (abs_value_c[0].clone() + abs_value_c[3].clone())
                    + z_0.clone()
                    + z_3.clone()),
        );

        // (is_mulh + is_mulhsu) ⋅ [P''3_l + P''3_h⋅2^8 + c''3⋅2^16 - (|b|1 + |b|2)⋅(|c|1 + |c|2) + z1 + z2]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (p3_prime_prime[0].clone()
                    + p3_prime_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime_prime.clone() * BaseField::from(1 << 16)
                    - (abs_value_b[1].clone() + abs_value_b[2].clone())
                        * (abs_value_c[1].clone() + abs_value_c[2].clone())
                    + z_1.clone()
                    + z_2.clone()),
        );

        // (is_mulh + is_mulhsu) ⋅ [P5_l + P5_h⋅2^8 + c5⋅2^16 - (|b|2 + |b|3)⋅(|c|2 + |c|3) + z2 + z3]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (p5[0].clone()
                    + p5[1].clone() * BaseField::from(1 << 8)
                    + c5.clone() * BaseField::from(1 << 16)
                    - (abs_value_b[2].clone() + abs_value_b[3].clone())
                        * (abs_value_c[2].clone() + abs_value_c[3].clone())
                    + z_2.clone()
                    + z_3.clone()),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);
        let [mul_carry_2_0] = trace_eval!(trace_eval, MulCarry2_0);
        let [mul_carry_2_1] = trace_eval!(trace_eval, MulCarry2_1);
        let [mul_carry_3] = trace_eval!(trace_eval, MulCarry3);

        let abs_value_a_low = trace_eval!(trace_eval, ValueAAbs);
        let abs_value_a_high = trace_eval!(trace_eval, ValueAAbsHigh);

        // (is_mulh + is_mulhsu) ⋅
        // (𝑧0 + 𝑃1_𝑙 ⋅ 2^8 − carry0 ⋅ 2^16 − |𝑎|0 − |𝑎|1 ⋅ 2^8)
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - abs_value_a_low[0].clone()
                    - abs_value_a_low[1].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) ⋅
        // [𝑧1 + 𝑃1ℎ + (𝑏0 + 𝑏2) ⋅ (𝑐0 + 𝑐2) − 𝑧0 − 𝑧2 + (𝑃′3𝑙 + 𝑃″3𝑙 + 𝑐1) ⋅ 2^8 + carry0 − carry1_0 ⋅ 2^16 − carry1_1 ⋅ 2^17 − |𝑎|2 − |𝑎|3 ⋅ 2^8]
        eval.add_constraint(
            (is_mulh.clone() + is_mulhsu.clone())
                * (z_1.clone()
                    + p1[1].clone()
                    + (abs_value_b[0].clone() + abs_value_b[2].clone())
                        * (abs_value_c[0].clone() + abs_value_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + mul_carry_0.clone()
                    - mul_carry_1_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_1_1.clone() * BaseField::from(1 << 17)
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    - abs_value_a_low[2].clone()
                    - abs_value_a_low[3].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) ⋅ [𝑧2 + 𝑃′3_ℎ + 𝑃″3_ℎ + (𝑏1 + 𝑏3) ⋅ (𝑐1 + 𝑐3) − 𝑧1 − 𝑧3 +
        // (𝑃5_𝑙 + 𝑐″3 + 𝑐′3) ⋅ 2^8 + carry1_0 + carry1_1 ⋅ 2^1 − carry2_0 ⋅ 2^16
        // − carry2_1 ⋅ 2^17 − |𝑎|0 − |𝑎|1 ⋅ 2^8]
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
                    + mul_carry_1_0.clone()
                    + mul_carry_1_1.clone() * BaseField::from(1 << 1)
                    - mul_carry_2_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_2_1.clone() * BaseField::from(1 << 17)
                    - abs_value_a_high[0].clone()
                    - abs_value_a_high[1].clone() * BaseField::from(1 << 8)),
        );

        // (is_mulh + is_mulhsu) ⋅
        // (𝑧3 + 𝑃5ℎ + 𝑐5 ⋅ 2^8 + carry2_0 + carry2_1 ⋅ 2^1 − carry3 ⋅ 2^16 − |𝑎|2 − |𝑎|3 ⋅ 2^8)
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

        let [is_zero_a] = trace_eval!(trace_eval, IsAZero);
        constraint_gadget_is_zero(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            is_zero_a.clone(),
            abs_value_a_low.clone(),
        );
        constraint_gadget_is_zero(
            eval,
            is_mulh.clone() + is_mulhsu.clone(),
            is_zero_a.clone(),
            abs_value_a_high.clone(),
        );

        let [sgn_a] = trace_eval!(trace_eval, SgnA);
        // The sign of the result depends on the sign of the valueB and valueC for MULH.
        constraint_gadget_sign_2_to_1(
            eval,
            is_mulh.clone(),
            sgn_a.clone(),
            is_zero_a.clone(),
            [sgn_b.clone(), sgn_c.clone()],
        );

        // The sign of the result depends on the sign of the valueB for MULHSU.
        constraint_gadget_sign_1_to_1(
            eval,
            is_mulhsu.clone(),
            sgn_a.clone(),
            is_zero_a.clone(),
            sgn_b.clone(),
        );

        let value_a = trace_eval!(trace_eval, ValueA);
        let value_a_low = trace_eval!(trace_eval, ValueALow);
        let abs_value_a_low_borrow = trace_eval!(trace_eval, ValueAAbsBorrow);
        let abs_value_a_high_borrow = trace_eval!(trace_eval, ValueAAbsBorrowHigh);
        // Check for absolute value of value_a is equal to abs_value_a_high
        constraint_gadget_abs64(
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
            AddChip, CpuChip, DecodingCheckChip, LuiChip, MulhMulhsuChip, ProgramMemCheckChip,
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
    fn test_k_trace_constrained_mulhhh_instructions() {
        let basic_block = setup_basic_mulh_block_ir();
        test_k_trace_constrained_instructions(basic_block);
    }
}
