use nexus_vm::riscv::BuiltinOpcode;
use num_traits::One;
use stwo_prover::core::fields::m31::BaseField;

use crate::{
    column::Column::{self, *},
    extensions::ExtensionsConfig,
    trace::eval::trace_eval,
    traits::MachineChip,
};

use super::{
    gadget::{
        constrain_absolute_32_bit, constrain_division_overflow, constrain_mul_partial_product,
        constrain_sign_1_to_1, constrain_sign_2_to_1, constrain_zero_word,
    },
    nexani::{abs_limb, divu_limb, mull_limb, AbsResult},
};

pub struct DivRemChip;

impl MachineChip for DivRemChip {
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
            Some(BuiltinOpcode::DIV) | Some(BuiltinOpcode::REM)
        ) {
            return;
        }

        let value_a = vm_step.get_result().expect("DIV or REM must have a result");
        let value_b = vm_step.get_value_b();
        let value_c = vm_step.get_value_c().0;

        let (remainder, quotient, is_c_zero, is_overflow) =
            match (i32::from_le_bytes(value_b), i32::from_le_bytes(value_c)) {
                // Division by zero case
                (_, 0) => {
                    let quotient = (-1i32).to_le_bytes(); // All 1's for DIV
                    let remainder = abs_limb(u32::from_le_bytes(value_b)); // For REM, return the dividend
                    (
                        remainder,
                        AbsResult {
                            abs_limbs: quotient,
                            carry: [false, false], // unused
                            sgn: true,
                        },
                        true,
                        false,
                    )
                }
                // Overflow case: MIN_INT / -1
                (i32::MIN, -1) => {
                    let quotient = i32::MIN.to_le_bytes();
                    let remainder = 0i32.to_le_bytes();
                    (
                        AbsResult {
                            abs_limbs: remainder,
                            carry: [false, false], // unused
                            sgn: false,            // unused
                        },
                        AbsResult {
                            abs_limbs: quotient,
                            carry: [false, false], // unused
                            sgn: true,
                        },
                        false,
                        true,
                    )
                }
                // Normal division case
                _ => {
                    let quotient =
                        i32::from_le_bytes(value_b).wrapping_div(i32::from_le_bytes(value_c));
                    let remainder =
                        i32::from_le_bytes(value_b).wrapping_rem(i32::from_le_bytes(value_c));
                    (
                        abs_limb(remainder as u32),
                        abs_limb(quotient as u32),
                        false,
                        false,
                    )
                }
            };

        traces.fill_columns(row_idx, is_c_zero, IsDivideByZero);
        traces.fill_columns(row_idx, is_overflow, IsOverflow);

        let abs_value_b = abs_limb(u32::from_le_bytes(value_b));
        let abs_value_c = abs_limb(u32::from_le_bytes(value_c));

        // The quotient is committed to the trace in absolute value, abs_quotient = |value_a| in case of DIV
        // In case of REM, we check that remainder = |value_a|
        traces.fill_columns(row_idx, quotient.abs_limbs, Quotient);
        if matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::DIV)
        ) {
            traces.fill_columns(row_idx, quotient.carry, ValueAAbsBorrow);
        } else {
            traces.fill_columns(row_idx, remainder.carry, ValueAAbsBorrow);
        }
        // Commit absolute value of the divisor and dividend
        traces.fill_columns(row_idx, abs_value_b.abs_limbs, ValueBAbs);
        traces.fill_columns(row_idx, abs_value_b.carry, ValueBAbsBorrow);
        traces.fill_columns(row_idx, abs_value_c.abs_limbs, ValueCAbs);
        traces.fill_columns(row_idx, abs_value_c.carry, ValueCAbsBorrow);

        // Calculate t = quotient * divisor using mull_limb (mul long limbs) to get intermediate values
        let mul_result = mull_limb(
            u32::from_le_bytes(quotient.abs_limbs),
            u32::from_le_bytes(abs_value_c.abs_limbs),
        );

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

        // Store t = quotient * divisor
        traces.fill_columns(row_idx, mul_result.a_l, HelperT);

        // Calculate the division results (remainder r, check value u)
        let divu_result = divu_limb(
            u32::from_le_bytes(quotient.abs_limbs),    // quotient
            u32::from_le_bytes(remainder.abs_limbs),   // remainder
            u32::from_le_bytes(abs_value_b.abs_limbs), // dividend
            u32::from_le_bytes(abs_value_c.abs_limbs), // divisor
        );

        // Store r = dividend - t
        traces.fill_columns(row_idx, divu_result.r, Remainder);
        traces.fill_columns(row_idx, divu_result.r_borrow[0], RemainderBorrow);
        // Store u = divisor - r - 1
        traces.fill_columns(row_idx, divu_result.u, HelperU);
        traces.fill_columns(row_idx, divu_result.u_borrow[0], HelperUBorrow);

        // Store original values needed in constraints
        traces.fill_columns(row_idx, value_a, ValueA); // Quotient/Remainder (rd)
        traces.fill_columns(row_idx, quotient.sgn, SgnA);
        traces.fill_columns(row_idx, abs_value_b.sgn, SgnB);
        traces.fill_columns(row_idx, abs_value_c.sgn, SgnC);

        traces.fill_columns(row_idx, vm_step.get_sgn_result(), SgnA);
        traces.fill_columns(row_idx, vm_step.get_sgn_b(), SgnB);
        traces.fill_columns(row_idx, vm_step.get_sgn_c(), SgnC);

        traces.fill_columns(row_idx, value_a == [0, 0, 0, 0], IsAZero);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &crate::components::AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_div] = trace_eval!(trace_eval, IsDiv);
        let [is_rem] = trace_eval!(trace_eval, IsRem);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let abs_dividend_b = trace_eval!(trace_eval, ValueBAbs);
        let abs_divisor_c = trace_eval!(trace_eval, ValueCAbs);
        let abs_value_b_borrow = trace_eval!(trace_eval, ValueBAbsBorrow);
        let abs_value_c_borrow = trace_eval!(trace_eval, ValueCAbsBorrow);

        let [sgn_b] = trace_eval!(trace_eval, SgnB);
        let [sgn_c] = trace_eval!(trace_eval, SgnC);
        let value_a = trace_eval!(trace_eval, ValueA);
        let [is_divide_by_zero] = trace_eval!(trace_eval, IsDivideByZero);
        let [is_a_zero] = trace_eval!(trace_eval, IsAZero);
        let [is_overflow] = trace_eval!(trace_eval, IsOverflow);

        // Check for is_divide_by_zero
        // (is_div + is_rem) ⋅ is_divide_by_zero ⋅ (c_0 + c_1 + c_2 + c_3)
        constrain_zero_word(
            eval,
            is_div.clone() + is_rem.clone(),
            is_divide_by_zero.clone(),
            value_c.clone(),
        );
        // Check for is_a_zero
        // (is_div + is_rem) ⋅ is_a_zero ⋅ (a_0 + a_1 + a_2 + a_3)
        constrain_zero_word(
            eval,
            is_div.clone() + is_rem.clone(),
            is_a_zero.clone(),
            value_a.clone(),
        );

        // Check for is_overflow when dividend is i32::MIN and divisor is -1
        constrain_division_overflow(
            eval,
            is_div.clone() + is_rem.clone(),
            is_overflow.clone(),
            value_b.clone(),
            value_c.clone(),
        );

        // Assert that the committed absolute value_b is equal to dividend
        // (is_div + is_rem) ⋅
        // [(1 − sgn_b) ⋅ (b_0 + b_1 ⋅ 2^8) + sgn_b ⋅ (2^16 − b_0 - b_1 ⋅ 2^8 - abs_value_b_borrow ⋅ 2^16) - dividend_0 - dividend_1 ⋅ 2^8]
        // (is_div + is_rem) ⋅
        // [(1 − sgn_b) ⋅ (b_2 + b_3 ⋅ 2^8) + sgn_b ⋅ (2^16 - 1 - b_2 - b_3 ⋅ 2^8 - abs_value_b_borrow_1 ⋅ 2^16 + abs_value_b_borrow_0) - dividend_2 - dividend_3 ⋅ 2^8]
        constrain_absolute_32_bit(
            eval,
            is_div.clone() + is_rem.clone(),
            sgn_b.clone(),
            value_b.clone(),
            abs_dividend_b.clone(),
            abs_value_b_borrow.clone(),
        );

        // Assert that the committed absolute value_c is equal to divisor
        // (is_div + is_rem) ⋅
        // [(1 − sgn_c) ⋅ (c_0 + c_1 ⋅ 2^8) + sgn_c ⋅ (2^16 − c_0 - c_1 ⋅ 2^8 - abs_value_c_borrow ⋅ 2^16) - divisor_0 - divisor_1 ⋅ 2^8]
        // (is_div + is_rem) ⋅
        // [(1 − sgn_c) ⋅ (c_2 + c_3 ⋅ 2^8) + sgn_c ⋅ (2^16 - 1 - c_2 - c_3 ⋅ 2^8 - abs_value_c_borrow_1 ⋅ 2^16 + abs_value_c_borrow_0) - divisor_2 - divisor_3 ⋅ 2^8]
        constrain_absolute_32_bit(
            eval,
            is_div.clone() + is_rem.clone(),
            sgn_c.clone(),
            value_c.clone(),
            abs_divisor_c.clone(),
            abs_value_c_borrow.clone(),
        );
        let quotient = trace_eval!(trace_eval, Quotient);
        let abs_value_a_borrow = trace_eval!(trace_eval, ValueAAbsBorrow);
        let [sgn_a] = trace_eval!(trace_eval, SgnA);

        // For REM, the sign of remainder is the same as the sign of dividend, except when overflow occurs
        constrain_sign_1_to_1(
            eval,
            is_rem.clone() * (E::F::one() - is_divide_by_zero.clone() - is_overflow.clone()),
            sgn_a.clone(),
            is_a_zero.clone(),
            sgn_b.clone(),
        );

        // For DIV, the sign of quotient is sign_b xor sign_c, except when valueC is zero and overflow occurs
        constrain_sign_2_to_1(
            eval,
            is_div.clone() * (E::F::one() - is_divide_by_zero.clone() - is_overflow.clone()),
            sgn_a.clone(),
            is_a_zero.clone(),
            [sgn_b.clone(), sgn_c.clone()],
        );

        // Assert that the committed absolute value_a is equal to quotient except when valueC is zero or overflow occurs
        // is_div ⋅
        // [(1 − sgn_a) ⋅ (a_0 + a_1 ⋅ 2^8) + sgn_a ⋅ (2^16 − a_0 - a_1 ⋅ 2^8 - abs_value_a_borrow ⋅ 2^16) - quotient_0 - quotient_1 ⋅ 2^8]
        constrain_absolute_32_bit(
            eval,
            is_div.clone() * (E::F::one() - is_divide_by_zero.clone() - is_overflow.clone()),
            sgn_a.clone(),
            value_a.clone(),
            quotient.clone(),
            abs_value_a_borrow.clone(),
        );

        let remainder = trace_eval!(trace_eval, Remainder);

        // Assert that the committed absolute value_a is equal to remainder
        // is_rem ⋅ [(1 − sgn_a) ⋅ (a_0 + a_1 ⋅ 2^8) + sgn_a ⋅ (2^16 - a_0 - a_1 ⋅ 2^8 - abs_value_a_borrow_0 ⋅ 2^16) - remainder_0 - remainder_1 ⋅ 2^8]
        // is_rem ⋅ [(1 − sgn_a) ⋅ (a_2 + a_3 ⋅ 2^8) + sgn_a ⋅ (2^16 - 1 - a_2 - a_3 ⋅ 2^8 - abs_value_a_borrow_1 ⋅ 2^16 + abs_value_a_borrow_0) - remainder_2 - remainder_3 ⋅ 2^8]
        constrain_absolute_32_bit(
            eval,
            is_rem.clone() * (E::F::one() - is_divide_by_zero.clone()),
            sgn_a.clone(),
            value_a.clone(),
            remainder.clone(),
            abs_value_a_borrow.clone(),
        );

        // Handle DIV exception:If divide_by_zero is true, then the result of the division is `-1`
        // When overflow occurs, the result of the division is `-2^31`
        eval.add_constraint(
            is_div.clone()
                * ((E::F::one() - is_divide_by_zero.clone() - is_overflow.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone() * BaseField::from(0xFFFF)
                    + is_overflow.clone() * BaseField::from(0)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_div.clone()
                * ((E::F::one() - is_divide_by_zero.clone() - is_overflow.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone() * BaseField::from(0xFFFF)
                    + is_overflow.clone() * BaseField::from(0x8000)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );
        // Handle REMU exception:If divide_by_zero is true, then the result of the remainder is the dividend (no absolute value)
        // When overflow occurs, the result of the remainder is 0
        eval.add_constraint(
            is_rem.clone()
                * ((E::F::one() - is_divide_by_zero.clone() - is_overflow.clone())
                    * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone()
                        * (value_b[0].clone() + value_b[1].clone() * BaseField::from(1 << 8))
                    + is_overflow.clone() * BaseField::from(0)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            is_rem.clone()
                * ((E::F::one() - is_divide_by_zero.clone() - is_overflow.clone())
                    * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8))
                    + is_divide_by_zero.clone()
                        * (value_b[2].clone() + value_b[3].clone() * BaseField::from(1 << 8))
                    + is_overflow.clone() * BaseField::from(0)
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)),
        );

        // Now, we verify the committed quotient and remainder are correct
        // We do this by verifying the following constraints:
        // 1. t = quotient * divisor is in 32-bit range
        // 2. r = dividend - t >= 0 and r is equal to the committed remainder
        // 3. u = divisor - r - 1 >= 0 when c != 0

        // Assert that the multiplication of quotient * divisor fits within 32 bits
        eval.add_constraint(
            (is_div.clone() + is_rem.clone())
                * ((quotient[2].clone() + quotient[3].clone())
                    * (abs_divisor_c[2].clone() + abs_divisor_c[3].clone())
                    + quotient[1].clone() * abs_divisor_c[3].clone()
                    + quotient[3].clone() * abs_divisor_c[1].clone()),
        );

        // Assert the intermediate values are correct for the t = quotient * divisor calculation
        let p1 = trace_eval!(trace_eval, MulP1);
        let p3_prime = trace_eval!(trace_eval, MulP3Prime);
        let p3_prime_prime = trace_eval!(trace_eval, MulP3PrimePrime);
        let [c1] = trace_eval!(trace_eval, MulC1);
        let [c3_prime] = trace_eval!(trace_eval, MulC3Prime);
        let [c3_prime_prime] = trace_eval!(trace_eval, MulC3PrimePrime);

        let z_0 = quotient[0].clone() * abs_divisor_c[0].clone();
        let z_1 = quotient[1].clone() * abs_divisor_c[1].clone();
        let z_2 = quotient[2].clone() * abs_divisor_c[2].clone();
        let z_3 = quotient[3].clone() * abs_divisor_c[3].clone();

        // (is_div + is_rem) ⋅
        // [P3' + c3' ⋅ 2^16 − (|b|0 + |b|3) ⋅ (|c|0 + |c|3) + z0 + z3]
        constrain_mul_partial_product(
            eval,
            is_div.clone() + is_rem.clone(),
            p3_prime.clone(),
            c3_prime.clone(),
            quotient[0].clone(),
            quotient[3].clone(),
            abs_divisor_c[0].clone(),
            abs_divisor_c[3].clone(),
            z_0.clone(),
            z_3.clone(),
        );

        // (is_div + is_rem) ⋅
        // [P3'' + c3'' ⋅ 2^16 − (|b|1 + |b|2) ⋅ (|c|1 + |c|2) + z1 + z2]
        constrain_mul_partial_product(
            eval,
            is_div.clone() + is_rem.clone(),
            p3_prime_prime.clone(),
            c3_prime_prime.clone(),
            quotient[1].clone(),
            quotient[2].clone(),
            abs_divisor_c[1].clone(),
            abs_divisor_c[2].clone(),
            z_1.clone(),
            z_2.clone(),
        );

        // (is_div + is_rem) ⋅
        // [P1 + c1 ⋅ 2^16 − (|b|0 + |b|1) ⋅ (|c|0 + |c|1) + z0 + z1]
        constrain_mul_partial_product(
            eval,
            is_div.clone() + is_rem.clone(),
            p1.clone(),
            c1.clone(),
            quotient[0].clone(),
            quotient[1].clone(),
            abs_divisor_c[0].clone(),
            abs_divisor_c[1].clone(),
            z_0.clone(),
            z_1.clone(),
        );

        let [mul_carry_0] = trace_eval!(trace_eval, MulCarry0);
        let [mul_carry_1] = trace_eval!(trace_eval, MulCarry1);

        let helper_t = trace_eval!(trace_eval, HelperT); // t = quotient * divisor

        // Constraint for low part of t = quotient * divisor
        // (is_div + is_rem) ⋅ (z0 + P1_l ⋅ 2^8 − carry0 ⋅ 2^16 − |t|0 − |t|1 * 2^8)
        eval.add_constraint(
            (is_div.clone() + is_rem.clone())
                * (z_0.clone() + p1[0].clone() * BaseField::from(1 << 8)
                    - mul_carry_0.clone() * BaseField::from(1 << 16)
                    - helper_t[0].clone()
                    - helper_t[1].clone() * BaseField::from(1 << 8)),
        );

        // Constraint for high part of t = quotient * divisor
        // (is_div + is_rem) ⋅
        // [z1 + P1h + (b0 + b2) ⋅ (c0 + c2) − z0 − z2 + (P′3l + P″3l + c1) ⋅ 2^8 + carry0 − carry1 ⋅ 2^16 − |t|2 − |t|3 ⋅ 2^8]
        eval.add_constraint(
            (is_div.clone() + is_rem.clone())
                * (z_1.clone()
                    + p1[1].clone()
                    + (quotient[0].clone() + quotient[2].clone())
                        * (abs_divisor_c[0].clone() + abs_divisor_c[2].clone())
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
            (is_div.clone() + is_rem.clone())
                * ((abs_dividend_b[0].clone()
                    + abs_dividend_b[1].clone() * BaseField::from(1 << 8)
                    + remainder_borrow.clone() * BaseField::from(1 << 16)) // remainder_borrow0 * 2^16
                   - (helper_t[0].clone()
                    + helper_t[1].clone() * BaseField::from(1 << 8)
                    + remainder[0].clone()
                    + remainder[1].clone() * BaseField::from(1 << 8))), // t_low + r_low
        );

        // High part: dividend_high = t_high + r_high + remainder_borrow0 (simplified)
        eval.add_constraint(
            (is_div.clone() + is_rem.clone())
                * ((abs_dividend_b[2].clone()
                    + abs_dividend_b[3].clone() * BaseField::from(1 << 8))
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
            (is_div.clone() + is_rem.clone())
                * (E::F::one() - is_divide_by_zero.clone())
                * ((abs_divisor_c[0].clone() + abs_divisor_c[1].clone() * BaseField::from(1 << 8)) // c_low
                   + helper_u_borrow.clone() * BaseField::from(1 << 16) // helper_u_borrow0 * 2^16
                   - remainder[0].clone() // r_low
                   - remainder[1].clone() * BaseField::from(1 << 8) // r_low
                   - E::F::one() // 1
                   - helper_u[0].clone()
                   - helper_u[1].clone() * BaseField::from(1 << 8)), // u_low
        );

        // High part: c_high = r_high + u_high + helper_u_borrow0 (simplified)
        eval.add_constraint(
            (is_div.clone() + is_rem.clone())
                * (E::F::one() - is_divide_by_zero.clone())
                * ((abs_divisor_c[2].clone() + abs_divisor_c[3].clone() * BaseField::from(1 << 8)) // c_high
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
            AddChip, CpuChip, DecodingCheckChip, LuiChip, ProgramMemCheckChip, RangeCheckChip,
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

    fn setup_basic_block_div_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Test basic division for DIV
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10), // x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 3),  // x2 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2),   // x3 = div(10, 3) = 3
            // Test division when divisor is 1 (should return dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 42), // x4 = 42
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 1),  // x5 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 6, 4, 5), // x6 = div(42, 1) = 42
            // Test division by 0 (should return all 1s, i.e., -1 in two's complement)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 5), // x7 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 9, 7, 8),  // x9 = div(5, 0) = -1
            // Test i32::MAX division
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 10, 0, 0x7FFFF), // x10 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 10, 0xFFF), // x10 = 0x7FFFFFFF (i32::MAX)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 2),      // x11 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 12, 10, 11), // x12 = div(i32::MAX, 2) = 0x3FFFFFFF
            // Test i32::MIN division
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 13, 0, 0x80000), // x13 = 0x80000000 (i32::MIN)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 13, 0xFFF), // x13 = 0x80000000 (i32::MIN)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 2),      // x14 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 15, 13, 14), // x15 = div(i32::MIN, 2) = 0x3FFFFFFF
            // Test division where dividend < divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 3), // x13 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 10), // x14 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 15, 13, 14), // x15 = div(3, 10) = 0
            // Test division where divisor equals dividend
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 0, 7), // x16 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, 7), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 18, 16, 17), // x18 = div(7, 7) = 1
            // Test division with large values
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 19, 0, 0x7FFFF), // x19 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 19, 0xFFF), // x19 = 0x7FFFFFFF (i32::MAX)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 20, 0, 0x40000), // x20 = 0x40000000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 21, 19, 20), // x21 = div(i32::MAX, 0x40000000) = 1
            // Test division where result is exactly 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 0), // x22 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 25), // x23 = 25
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 24, 22, 23), // x24 = div(0, 25) = 0
            // Test division where result is exactly 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 0), // x22 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 25), // x23 = 25
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 23, 0, 23), // x23 = 0 - 25 = -25
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 24, 22, 23), // x24 = div(0, -25) = 0
            // Test negative number division
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 25, 0, 10), // x25 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 25, 0, 25),  // x25 = 0 - 10 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 26, 0, 3),  // x26 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 27, 25, 26), // x27 = div(-10, 3) = -3
            // Test division with both negative numbers
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 28, 0, 20), // x28 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 28, 0, 28),  // x28 = 0 - 20 = -20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 29, 0, 4),  // x29 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 29, 0, 29),  // x29 = 0 - 4 = -4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 30, 28, 29), // x30 = div(-20, -4) = 5
            // Test overflow case (MIN_INT / -1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 1, 0, 0x80000), // x1 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 31, 0, 1),     // x31 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 31, 0, 31), // x31 = 0 - 1 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 2, 1, 31), // x2 = div(MIN_INT, -1) = overflow (should return MIN_INT
            // Test division with all sign combinations (positive/negative)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 11), // x3 = 11 (positive dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 3), // x4 = 3 (positive divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 5, 3, 4), // x5 = div(11, 3) = 3 (positive result)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 0, 11), // x6 = 11 (positive dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 3),  // x7 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 7, 0, 7), // x7 = -3 (negative divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 8, 6, 7), // x8 = div(11, -3) = -3 (negative result)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 9, 0, 11), // x9 = 11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 9), // x9 = -11 (negative dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 3), // x10 = 3 (positive divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 11, 9, 10), // x11 = div(-11, 3) = -3 (negative result)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 12, 0, 11), // x12 = 11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 12, 0, 12), // x12 = -11 (negative dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 3), // x13 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 13, 0, 13), // x13 = -3 (negative divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 14, 12, 13), // x14 = div(-11, -3) = 3 (positive result)
            // Test division with power of 2 divisors
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 15, 0, 32), // x15 = 32
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 0, 8), // x16 = 8 (power of 2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 17, 15, 16), // x17 = div(32, 8) = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 18, 0, 32), // x18 = 32
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 8),  // x19 = 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 19, 0, 19), // x19 = -8 (negative power of 2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 20, 18, 19), // x20 = div(32, -8) = -4
            // Additional tests for DIV with zero divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 21, 0, 42), // x21 = 42 (positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 0),  // x22 = 0 (divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 23, 21, 22), // x23 = div(42, 0) = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 24, 0, 42), // x24 = 42
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 24, 0, 24), // x24 = -42 (negative)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 25, 0, 0), // x25 = 0 (divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 26, 24, 25), // x26 = div(-42, 0) = -1
            // Additional tests for DIV overflow cases
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 27, 0, 0x80000), // x27 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 28, 0, 1),      // x28 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 28, 0, 28),      // x28 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 29, 27, 28), // x29 = div(MIN_INT, -1) = MIN_INT (overflow)
        ]);
        vec![basic_block]
    }

    fn setup_basic_block_rem_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Test basic remainder for REM
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10), // x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 3),  // x2 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2),   // x3 = rem(10, 3) = 1
            // Test remainder when divisor is 1 (should always be 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 42), // x4 = 42
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 1),  // x5 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 6, 4, 5),   // x6 = rem(42, 1) = 0
            // Test remainder by 0 (should return dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 5), // x7 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 0), // x8 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 9, 7, 8),  // x9 = rem(5, 0) = 5
            // Test i32::MAX remainder
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 10, 0, 0x7FFFF), // x10 = 0x7FFFF000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 10, 0xFFF), // x10 = 0x7FFFFFFF (i32::MAX)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 11, 0, 2),      // x11 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 12, 10, 11), // x12 = rem(i32::MAX, 2) = 1
            // Test remainder where dividend < divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 13, 0, 3), // x13 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 14, 0, 10), // x14 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 15, 13, 14), // x15 = rem(3, 10) = 3
            // Test remainder where divisor equals dividend
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 16, 0, 7), // x16 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, 7), // x17 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 18, 16, 17), // x18 = rem(7, 7) = 0
            // Test negative number remainder
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 19, 0, 10), // x19 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 19, 0, 19),  // x19 = 0 - 10 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 20, 0, 3),  // x20 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 21, 19, 20), // x21 = rem(-10, 3) = -1
            //    Test remainder with both negative numbers
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 20), // x22 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 22, 0, 22),  // x22 = 0 - 20 = -20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 4),  // x23 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 23, 0, 23),  // x23 = 0 - 4 = -4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 24, 22, 23), // x24 = rem(-20, -4) = 0
            // Test positive dividend, negative divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 25, 0, 17), // x25 = 17
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 26, 0, 5),  // x26 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 26, 0, 26),  // x26 = 0 - 5 = -5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 27, 25, 26), // x27 = rem(17, -5) = 2
            // Test overflow case (MIN_INT % -1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 28, 0, 0x80000), // x28 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 29, 0, 1),      // x29 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 29, 0, 29), // x29 = 0 - 1 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 30, 28, 29), // x30 = rem(MIN_INT, -1) = 0
            // Test remainder with all sign combinations
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 31, 0, 11), // x31 = 11 (positive dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 4), // x1 = 4 (positive divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 2, 31, 1), // x2 = rem(11, 4) = 3 (positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 11), // x3 = 11 (positive dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 4),  // x4 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4), // x4 = -4 (negative divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 5, 3, 4), // x5 = rem(11, -4) = 3 (positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 0, 11), // x6 = 11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 6, 0, 6), // x6 = -11 (negative dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 4), // x7 = 4 (positive divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 8, 6, 7), // x8 = rem(-11, 4) = -3 (negative)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 9, 0, 11), // x9 = 11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 9, 0, 9), // x9 = -11 (negative dividend)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 4), // x10 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 10, 0, 10), // x10 = -4 (negative divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 11, 9, 10), // x11 = rem(-11, -4) = -3 (negative)
            // Additional tests for REM with zero divisor
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 123), // x1 = 123 (positive)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 0),   // x2 = 0 (divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 3, 1, 2), // x3 = rem(123, 0) = 123
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 123), // x4 = 123
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 4), // x4 = -123 (negative)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 0), // x5 = 0 (divisor)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 6, 4, 5), // x6 = rem(-123, 0) = -123
            // Additional tests for REM overflow cases
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 7, 0, 0x80000), // x7 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 1),      // x8 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 8, 0, 8),       // x8 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 9, 7, 8), // x9 = rem(MIN_INT, -1) = 0 (no remainder)
        ]);
        vec![basic_block]
    }

    fn test_k_trace_constrained_instructions(basic_block: Vec<BasicBlock>) {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            LuiChip,
            DivRemChip,
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
    fn test_k_trace_constrained_div_instructions() {
        let basic_block = setup_basic_block_div_ir();
        test_k_trace_constrained_instructions(basic_block);
    }

    #[test]
    fn test_k_trace_constrained_remm_instructions() {
        let basic_block = setup_basic_block_rem_ir();
        test_k_trace_constrained_instructions(basic_block);
    }

    fn setup_comprehensive_div_rem_tests() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Setup useful constants
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 30, 0, 1), // x30 = 1 for MAX_UINT construction
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 31, 0, 30), // x31 = 0 - 1 = 0xFFFFFFFF (MAX_UINT)
            // --- Power of 2 Division Tests ---
            // 16 / 4 = 4, 16 % 4 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 16), // x1 = 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 4),  // x2 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2),   // x3 = 16/4 = 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 4, 1, 2),   // x4 = 16%4 = 0
            // 15 / 4 = 3, 15 % 4 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 15), // x5 = 15
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 6, 5, 2),   // x6 = 15/4 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 7, 5, 2),   // x7 = 15%4 = 3
            // --- Sign Combination Tests ---
            // Positive / Positive: 11 / 3 = 3, 11 % 3 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 11), // x8 = 11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 9, 0, 3),  // x9 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 10, 8, 9),  // x10 = 11/3 = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 11, 8, 9),  // x11 = 11%3 = 2
            // Positive / Negative: 11 / -3 = -3, 11 % -3 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 12, 0, 9), // x12 = -3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 13, 8, 12), // x13 = 11/(-3) = -3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 14, 8, 12), // x14 = 11%(-3) = 2
            // Negative / Positive: -11 / 3 = -3, -11 % 3 = -2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 15, 0, 8), // x15 = -11
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 16, 15, 9), // x16 = (-11)/3 = -3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 17, 15, 9), // x17 = (-11)%3 = -2
            // Negative / Negative: -11 / -3 = 3, -11 % -3 = -2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 18, 15, 12), // x18 = (-11)/(-3) = 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 19, 15, 12), // x19 = (-11)%(-3) = -2
            // --- Boundary Cases ---
            // 1 / 1 = 1, 1 % 1 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 20, 30, 30), // x20 = 1/1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 21, 30, 30), // x21 = 1%1 = 0
            // 0 / 5 = 0, 0 % 5 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 22, 0, 0), // x22 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 23, 0, 5), // x23 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 24, 22, 23), // x24 = 0/5 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 25, 22, 23), // x25 = 0%5 = 0
            // --- Special Cases ---
            // Division by zero: 7 / 0 = -1, 7 % 0 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 26, 0, 7), // x26 = 7
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 27, 26, 22), // x27 = 7/0 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 28, 26, 22), // x28 = 7%0 = 7
            // Overflow case: MIN_INT / -1 = MIN_INT, MIN_INT % -1 = 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 1, 0, 0x80000), // x1 = 0x80000000 (MIN_INT)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 2, 0, 30),      // x2 = -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::DIV), 3, 1, 2), // x3 = MIN_INT/(-1) = MIN_INT (overflow)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::REM), 4, 1, 2), // x4 = MIN_INT%(-1) = 0
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_comprehensive_div_rem() {
        let basic_block = setup_comprehensive_div_rem_tests();
        test_k_trace_constrained_instructions(basic_block);
    }
}
