use nexus_vm::riscv::BuiltinOpcode;
use num_traits::One;
use stwo_prover::core::fields::m31::BaseField;

use crate::{
    chips::instructions::mulhu::mulh_limb,
    column::Column::{self, *},
    extensions::ExtensionsConfig,
    trace::eval::trace_eval,
    traits::MachineChip,
};

use super::mul::mul_limb;

pub struct DivResult {
    // Remainder: r = a - b * c = a - t
    pub r: [u8; 4],
    // Borrows for r = a - t calculation
    pub r_borrow: [bool; 2],
    // Check value: u = c - r - 1
    pub u: [u8; 4],
    // Borrows for u = c - r - 1 calculation
    pub u_borrow: [bool; 2],
}

// This function verifies the relationship a = b * c + r, where 0 <= r < c.
// It computes t = b * c, r = a - t, and u = c - r - 1.
// It asserts that the intermediate borrow flags are as expected,
// specifically that r >= 0 (borrow_1 is false) and u >= 0 (borrow_3 is false).
// This implies 0 <= r < c.
//
// Preconditions:
// - b * c must fit within a u32 (checked by mul_limb result t.a_h == [0; 4]).
// - The specific implementation details of mul_limb might impose further constraints
//   (e.g., related to t.c5, t.p3_prime_prime, etc.), which are asserted here.
pub fn divu_limb(quotient: u32, remainder: u32, dividend: u32, divisor: u32) -> DivResult {
    let dividend_bytes = dividend.to_le_bytes();
    let divisor_bytes = divisor.to_le_bytes();
    let quotient_bytes = quotient.to_le_bytes();
    let remainder_bytes = remainder.to_le_bytes();

    // When divisor is 0, for DIVU, the result is 2^32 - 1
    // For REMU, the result is the dividend
    if divisor == 0 {
        return DivResult {
            r: [
                dividend_bytes[0],
                dividend_bytes[1],
                dividend_bytes[2],
                dividend_bytes[3],
            ],
            r_borrow: [false, false],
            // u = c - r - 1 >= 0 is not possible when c = 0, thus we set u to 0
            u: [0, 0, 0, 0],
            u_borrow: [false, false],
        };
    }

    // Calculate t = quotient * divisor
    let t = mulh_limb(quotient, divisor);
    // t.a_l contains the low 32 bits of quotient * divisor
    let quotient_divisor_bytes = t._a_l;

    // Assert that quotient * divisor fits within 32 bits (high part of multiplication is zero)
    assert_eq!(
        t._a_h,
        [0, 0, 0, 0],
        "Overflow: quotient * divisor exceeds u32::MAX"
    );

    // Assertions based on mul_limb internal details/constraints
    // These might be specific to the circuit implementation relying on mul_limb
    assert_eq!(t.c5, false);
    assert_eq!(t.p3_prime_prime[1], 0);
    assert_eq!(t.c3_prime_prime, false);
    assert_eq!(t.c3_prime, false);
    assert_eq!(t.p3_prime[1], 0);
    assert_eq!(t.carry_l[1], 0);

    // The above assertions can be combined into a single assertion
    {
        let quotient_bytes = quotient_bytes.map(|x| x as u32);
        let divisor_bytes = divisor_bytes.map(|x| x as u32);
        assert_eq!(
            (quotient_bytes[2] + quotient_bytes[3]) * (divisor_bytes[2] + divisor_bytes[3])
                + quotient_bytes[1] * divisor_bytes[3]
                + quotient_bytes[3] * divisor_bytes[1],
            0
        );
    }

    // Calculate r = a - t = (a - bc) using 16-bit chunks
    let a_low = u16::from_le_bytes([dividend_bytes[0], dividend_bytes[1]]);
    let bc_low = u16::from_le_bytes([quotient_divisor_bytes[0], quotient_divisor_bytes[1]]);
    let (r_low, borrow_0) = a_low.borrowing_sub(bc_low, false);

    let a_high = u16::from_le_bytes([dividend_bytes[2], dividend_bytes[3]]);
    let bc_high = u16::from_le_bytes([quotient_divisor_bytes[2], quotient_divisor_bytes[3]]);
    // Propagate borrow from the low part subtraction
    let (r_high, borrow_1) = a_high.borrowing_sub(bc_high, borrow_0);

    // Combine the 16-bit results back into r_bytes
    let r_bytes = [
        r_low.to_le_bytes()[0],
        r_low.to_le_bytes()[1],
        r_high.to_le_bytes()[0],
        r_high.to_le_bytes()[1],
    ];

    assert_eq!(r_bytes, remainder_bytes, "Remainder is incorrect");

    // Verify the subtraction r = a - bc
    let r_val = u32::from_le_bytes(r_bytes);
    let bc_val = u32::from_le_bytes(quotient_divisor_bytes);
    assert_eq!(r_val, dividend.wrapping_sub(bc_val));

    // Verify the low part subtraction: r_low + borrow_0 * 2^16 = bc_low + r_low
    assert_eq!(
        a_low as u32 + ((borrow_0 as u32) << 16),
        bc_low as u32 + r_low as u32,
        "Low part subtraction check failed"
    );

    // Verify the high part subtraction: a_high + borrow_1 * 2^16 = bc_high + r_high + borrow_0
    assert_eq!(
        a_high as u32 + ((borrow_1 as u32) << 16),
        bc_high as u32 + r_high as u32 + borrow_0 as u32,
        "High part subtraction check failed"
    );
    // Check if r >= 0. This is the core requirement for standard division remainder.
    // If a >= bc, borrow_1 would be false.
    assert_eq!(borrow_1, false, "Remainder r is negative (a < b*c)");

    // Calculate u = c - r - 1
    // This check helps ensure r < c. If c - r - 1 >= 0, then c - r > 0, so c > r.
    let c_low = u16::from_le_bytes([divisor_bytes[0], divisor_bytes[1]]);
    // Start with an initial borrow of 1 for the "- 1" part
    let (u_low, borrow_2) = c_low.borrowing_sub(r_low, true);

    let c_high = u16::from_le_bytes([divisor_bytes[2], divisor_bytes[3]]);
    // Propagate borrow from the low part subtraction
    let (u_high, borrow_3) = c_high.borrowing_sub(r_high, borrow_2);

    // Combine the 16-bit results back into u_bytes
    let u_bytes = [
        u_low.to_le_bytes()[0],
        u_low.to_le_bytes()[1],
        u_high.to_le_bytes()[0],
        u_high.to_le_bytes()[1],
    ];

    // Verify the subtraction u = c - r - 1
    let u_val = u_low as u32 + ((u_high as u32) << 16);
    assert_eq!(u_val, divisor.wrapping_sub(r_val).wrapping_sub(1));

    // Check if u >= 0 (i.e., c - r - 1 >= 0 => c > r).
    // If c <= r, borrow_3 must be false.
    assert_eq!(borrow_3, false, "Check u >= 0 failed (c <= r)");

    // An explicit check that c >= r, which is implied by borrow_3 == false if r is non-negative.
    assert!(divisor >= r_val, "Constraint c >= r failed");

    DivResult {
        r: r_bytes, // r = a - t
        r_borrow: [borrow_0, borrow_1],
        u: u_bytes, // u = c - r - 1
        u_borrow: [borrow_2, borrow_3],
    }
}

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
        let mul_result = mul_limb(u32::from_le_bytes(quotient), u32::from_le_bytes(value_c));

        // Fill in the intermediate values from mul_limb(quotient, divisor) into traces
        // These are needed for the multiplication constraints that verify t = quotient * divisor
        traces.fill_columns(row_idx, mul_result.carry_l[0], MulCarry0);
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

        traces.fill_columns(row_idx, value_c == [0, 0, 0, 0], IsCZero);
        // Store t = quotient * divisor
        traces.fill_columns(row_idx, mul_result._a_l, HelperT);

        // Calculate the division results (remainder r, check value u)
        let divu_result = divu_limb(
            u32::from_le_bytes(quotient),  // quotient
            u32::from_le_bytes(remainder), // remainder
            u32::from_le_bytes(value_b),   // dividend
            u32::from_le_bytes(value_c),   // divisor
        );

        // Store r = dividend - (quotient * divisor)
        traces.fill_columns(row_idx, divu_result.r, Remainder);
        traces.fill_columns(row_idx, divu_result.r_borrow, RemainderBorrow);
        // Store u = divisor - r - 1
        traces.fill_columns(row_idx, divu_result.u, HelperU);
        traces.fill_columns(row_idx, divu_result.u_borrow, HelperUBorrow);

        // Store original values needed in constraints
        traces.fill_columns(row_idx, value_a, ValueA); // Quotient/Remainder (rd)
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_divu] = trace_eval!(trace_eval, IsDivu);
        let [is_remu] = trace_eval!(trace_eval, IsRemu);
        let [is_c_zero] = trace_eval!(trace_eval, IsCZero);
        let dividend = trace_eval!(trace_eval, ValueB);
        let divisor_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);

        // Check for is_c_zero
        // (is_div + is_rem) ⋅ ((c_0 + c_1 ⋅ 2^8 + c_2 ⋅ 2^16 + c_3 ⋅ 2^22) ⋅ is_c_zero
        // + (1 - is_c_zero) ⋅ (c_0 + c_1 ⋅ 2^8 + c_2 ⋅ 2^16 + c_3 ⋅ 2^22)
        // - (c_0 + c_1 ⋅ 2^8 + c_2 ⋅ 2^16 + c_3 ⋅ 2^22))
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (is_c_zero.clone()
                    * (divisor_c[0].clone()
                        + divisor_c[1].clone() * BaseField::from(1 << 8)
                        + divisor_c[2].clone() * BaseField::from(1 << 16)
                        + divisor_c[3].clone() * BaseField::from(1 << 22))
                    + (E::F::one() - is_c_zero.clone())
                        * (divisor_c[0].clone()
                            + divisor_c[1].clone() * BaseField::from(1 << 8)
                            + divisor_c[2].clone() * BaseField::from(1 << 16)
                            + divisor_c[3].clone() * BaseField::from(1 << 22))
                    - (divisor_c[0].clone()
                        + divisor_c[1].clone() * BaseField::from(1 << 8)
                        + divisor_c[2].clone() * BaseField::from(1 << 16)
                        + divisor_c[3].clone() * BaseField::from(1 << 22))),
        );

        // Handle DIVU exception:If C is zero, then the result of the division is 2^32 - 1
        eval.add_constraint(
            is_divu.clone()
                * ((E::F::one() - is_c_zero.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_c_zero.clone() * E::F::from(BaseField::from(0xFFFF))
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_divu.clone()
                * ((E::F::one() - is_c_zero.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_c_zero.clone() * E::F::from(BaseField::from(0xFFFF))
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
        // Handle REMU exception:If C is zero, then the result of the remainder is the dividend
        eval.add_constraint(
            is_remu.clone()
                * ((E::F::one() - is_c_zero.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_c_zero.clone()
                        * (dividend[0].clone() + dividend[1].clone() * BaseField::from(1 << 8))
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_remu.clone()
                * ((E::F::one() - is_c_zero.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_c_zero.clone()
                        * (dividend[2].clone() + dividend[3].clone() * BaseField::from(1 << 8))
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );

        let quotient = trace_eval!(trace_eval, Quotient);
        let remainder = trace_eval!(trace_eval, Remainder);
        // Assert that the committed Quotient is equal to value_a
        eval.add_constraint(
            is_divu.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - quotient[0].clone()
                    - quotient[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_divu.clone()
                * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)
                    - quotient[2].clone()
                    - quotient[3].clone() * BaseField::from(1 << 8)),
        );
        // Assert that the committed Remainder is equal to value_a
        eval.add_constraint(
            is_remu.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - remainder[0].clone()
                    - remainder[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_remu.clone()
                * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)
                    - remainder[2].clone()
                    - remainder[3].clone() * BaseField::from(1 << 8)),
        );

        // Now, we verify the committed quotient and remainder are correct
        // We do this by verifying the following constraints:
        // 1. t = quotient * divisor is in 32-bit range
        // 2. r = divident - t >= 0 and r is equal to the committed remainder
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

        // (is_mul + is_mulh + is_mulhu + is_mulhsu + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 ′3 + 𝑐′3 ⋅ 2^16 − (|𝑏|0 + |𝑏|3) ⋅ (|𝑐|0 + |𝑐|3) + 𝑧0 + 𝑧3]
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (p3_prime[0].clone()
                    + p3_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime.clone() * BaseField::from(1 << 16)
                    - (quotient[0].clone() + quotient[3].clone())
                        * (divisor_c[0].clone() + divisor_c[3].clone())
                    + z_0.clone()
                    + z_3.clone()),
        );

        // (is_mul + is_mulh + is_mulhu + is_mulhsu + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 ″3 + 𝑐″3 ⋅ 2^16 − (|𝑏|1 + |𝑏|2) ⋅ (|𝑐|1 + |𝑐|2) + 𝑧1 + 𝑧2]
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (p3_prime_prime[0].clone()
                    + p3_prime_prime[1].clone() * BaseField::from(1 << 8)
                    + c3_prime_prime.clone() * BaseField::from(1 << 16)
                    - (quotient[1].clone() + quotient[2].clone())
                        * (divisor_c[1].clone() + divisor_c[2].clone())
                    + z_1.clone()
                    + z_2.clone()),
        );

        // (is_mul + is_div + is_divu + is_rem + is_remu) ⋅
        // [𝑃 1 + 𝑐1 ⋅ 2^16 − (|𝑏|0 + |𝑏|1) ⋅ (|𝑐|0 + |𝑐|1) + 𝑧0 + 𝑧1]
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (p1[0].clone()
                    + p1[1].clone() * BaseField::from(1 << 8)
                    + c1.clone() * BaseField::from(1 << 16)
                    - (quotient[0].clone() + quotient[1].clone())
                        * (divisor_c[0].clone() + divisor_c[1].clone())
                    + z_0.clone()
                    + z_1.clone()),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1_0] = trace_eval!(trace_eval, MulCarry1_0);
        let [mul_carry_1_1] = trace_eval!(trace_eval, MulCarry1_1);

        let helper_t = trace_eval!(trace_eval, HelperT); // t = quotient * divisor

        // Constraint for low part of t = quotient * divisor
        // (is_divu + is_remu) ⋅ (z0 + P1_l ⋅ 2^8 − carry0 ⋅ 2^16 − |t|0 − |t|1)
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - helper_t[0].clone()
                    - helper_t[1].clone() * BaseField::from(1 << 8)),
        );

        // Constraint for high part of t = quotient * divisor
        // is_divu ⋅
        // [z1 + P1h + (b0 + b2) ⋅ (c0 + c2) − z0 − z2 +(P′3l + P″3l + c1) ⋅ 2^8 + carry0 − carry1 ⋅ 2^16 − |t|2 − |t|3]
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (z_1.clone()
                    + p1[1].clone()
                    + (quotient[0].clone() + quotient[2].clone())
                        * (divisor_c[0].clone() + divisor_c[2].clone())
                    - z_0.clone()
                    - z_2.clone()
                    + mul_carry_0.clone()
                    - mul_carry_1_0.clone() * BaseField::from(1 << 16)
                    - mul_carry_1_1.clone() * BaseField::from(1 << 17)
                    + (p3_prime[0].clone() + p3_prime_prime[0].clone() + c1.clone())
                        * BaseField::from(1 << 8)
                    - helper_t[2].clone()
                    - helper_t[3].clone() * BaseField::from(1 << 8)),
        );

        let remainder_borrow = trace_eval!(trace_eval, RemainderBorrow); // borrow for r = dividend - t

        // Assert the calculation of r = dividend - t, rearranged as dividend = t + r
        // Low part: dividend_low + borrow0 * 2^16 = t_low + r_low
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * ((dividend[0].clone()
                    + dividend[1].clone() * BaseField::from(1 << 8)
                    + remainder_borrow[0].clone() * BaseField::from(1 << 16)) // borrow0 * 2^16
                   - (helper_t[0].clone()
                    + helper_t[1].clone() * BaseField::from(1 << 8)
                    + remainder[0].clone())
                    + remainder[1].clone() * BaseField::from(1 << 8)), // t_low + r_low
        );

        // High part: dividend_high + borrow1 * 2^16 = t_high + r_high + borrow0
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * ((dividend[2].clone()
                    + dividend[3].clone() * BaseField::from(1 << 8)
                    + remainder_borrow[1].clone() * BaseField::from(1 << 16)) // borrow1 * 2^16
                    - remainder_borrow[0].clone() // borrow0
                   - (helper_t[2].clone()
                    + helper_t[3].clone() * BaseField::from(1 << 8)
                    + remainder[2].clone()
                    + remainder[3].clone() * BaseField::from(1 << 8))), // t_high + r_high
        );

        // Assert remainder non-negative: r >= 0 (borrow1 must be 0)
        eval.add_constraint(is_divu.clone() * remainder_borrow[1].clone());

        // Check u = c - r - 1 >= 0
        // Low part: c_low + borrow2 * 2^16 = r_low + u_low + 1
        let helper_u = trace_eval!(trace_eval, HelperU); // u
        let helper_u_borrow = trace_eval!(trace_eval, HelperUBorrow); // borrow for c - r - 1
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (E::F::one() - is_c_zero.clone())
                * ((divisor_c[0].clone() + divisor_c[1].clone() * BaseField::from(1 << 8)) // c_low
                   + helper_u_borrow[0].clone() * BaseField::from(1 << 16) // borrow2 * 2^16
                   - remainder[0].clone() // r_low
                   - remainder[1].clone() * BaseField::from(1 << 8) // r_low
                   - E::F::one() // 1
                   - helper_u[0].clone()
                   - helper_u[1].clone() * BaseField::from(1 << 8)), // u_low
        );

        // High part: c_high + borrow3 * 2^16 = r_high + u_high + borrow2
        eval.add_constraint(
            (is_divu.clone() + is_remu.clone())
                * (E::F::one() - is_c_zero.clone())
                * ((divisor_c[2].clone() + divisor_c[3].clone() * BaseField::from(1 << 8)) // c_high
                    + helper_u_borrow[1].clone() * BaseField::from(1 << 16) // borrow3 * 2^16
                    - remainder[2].clone() // r_high
                    - remainder[3].clone() * BaseField::from(1 << 8) // r_high
                    - helper_u_borrow[0].clone() // borrow2
                    - helper_u[2].clone()
                    - helper_u[3].clone() * BaseField::from(1 << 8)), // u_high
        );

        // Assert check value non-negative: u >= 0 (borrow3 must be 0)
        eval.add_constraint((is_divu.clone() + is_remu.clone()) * helper_u_borrow[1].clone());
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, DivuRemuChip, ProgramMemCheckChip, RangeCheckChip,
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
}
