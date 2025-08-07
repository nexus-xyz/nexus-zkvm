use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

fn constrain_equal<E: EvalAtRow>(eval: &mut E, selector: E::F, lhs: E::F, rhs: E::F) {
    eval.add_constraint(selector * (lhs - rhs));
}

pub(super) fn constrain_absolute_32_bit<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn: E::F,
    value: [E::F; 4],
    abs_value: [E::F; 4],
    abs_value_borrow: [E::F; 2],
) {
    constrain_equal(
        eval,
        selector.clone(),
        (E::F::one() - sgn.clone())
            * (value[0].clone() + value[1].clone() * BaseField::from(1 << 8))
            + sgn.clone()
                * (E::F::from(BaseField::from(1 << 16))
                    - value[0].clone()
                    - value[1].clone() * BaseField::from(1 << 8)
                    - abs_value_borrow[0].clone() * BaseField::from(1 << 16)),
        abs_value[0].clone() + abs_value[1].clone() * BaseField::from(1 << 8),
    );

    constrain_equal(
        eval,
        selector.clone(),
        (E::F::one() - sgn.clone())
            * (value[2].clone() + value[3].clone() * BaseField::from(1 << 8))
            + sgn.clone()
                * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                    - value[2].clone()
                    - value[3].clone() * BaseField::from(1 << 8)
                    - abs_value_borrow[1].clone() * BaseField::from(1 << 16)
                    + abs_value_borrow[0].clone()),
        abs_value[2].clone() + abs_value[3].clone() * BaseField::from(1 << 8),
    );
}

pub(super) fn constrain_absolute_64_bit<E: EvalAtRow>(
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
    constrain_absolute_32_bit(
        eval,
        selector.clone(),
        sgn.clone(),
        value_low,
        abs_value_low,
        abs_value_low_borrow.clone(),
    );

    constrain_equal(
        eval,
        selector.clone(),
        (E::F::one() - sgn.clone())
            * (value_high[0].clone() + value_high[1].clone() * BaseField::from(1 << 8))
            + sgn.clone()
                * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                    - value_high[0].clone()
                    - value_high[1].clone() * BaseField::from(1 << 8)
                    - abs_value_high_borrow[0].clone() * BaseField::from(1 << 16)
                    + abs_value_low_borrow[1].clone()),
        abs_value_high[0].clone() + abs_value_high[1].clone() * BaseField::from(1 << 8),
    );

    constrain_equal(
        eval,
        selector.clone(),
        (E::F::one() - sgn.clone())
            * (value_high[2].clone() + value_high[3].clone() * BaseField::from(1 << 8))
            + sgn.clone()
                * (E::F::from(BaseField::from_u32_unchecked((1 << 16) - 1))
                    - value_high[2].clone()
                    - value_high[3].clone() * BaseField::from(1 << 8)
                    - abs_value_high_borrow[1].clone() * BaseField::from(1 << 16)
                    + abs_value_high_borrow[0].clone()),
        abs_value_high[2].clone() + abs_value_high[3].clone() * BaseField::from(1 << 8),
    );
}

pub(super) fn constrain_zero_word<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    is_zero: E::F,
    value: [E::F; 4],
) {
    constrain_equal(
        eval,
        selector,
        is_zero.clone()
            * (value[0].clone() + value[1].clone() + value[2].clone() + value[3].clone()),
        E::F::zero(),
    );
}

pub(super) fn constrain_sign_2_to_1<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn_out: E::F,
    is_out_zero: E::F,
    sgn_in: [E::F; 2],
) {
    constrain_equal(
        eval,
        selector,
        sgn_out,
        (E::F::one() - is_out_zero)
            * (sgn_in[0].clone() + sgn_in[1].clone()
                - sgn_in[0].clone() * sgn_in[1].clone() * BaseField::from_u32_unchecked(2)),
    );
}

pub(super) fn constrain_sign_1_to_1<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    sgn_out: E::F,
    is_out_zero: E::F,
    sgn_in: E::F,
) {
    constrain_equal(
        eval,
        selector,
        sgn_out,
        (E::F::one() - is_out_zero) * sgn_in,
    );
}

pub(super) fn constrain_mul_partial_product<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    p: [E::F; 2],
    carry: E::F,
    bx: E::F,
    by: E::F,
    cx: E::F,
    cy: E::F,
    zx: E::F,
    zy: E::F,
) {
    constrain_equal(
        eval,
        selector,
        p[0].clone() + p[1].clone() * BaseField::from(1 << 8) + carry * BaseField::from(1 << 16),
        (bx + by) * (cx + cy) - zx - zy,
    );
}

pub(super) fn constrain_division_overflow<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    is_overflow: E::F,
    dividend: [E::F; 4],
    divisor: [E::F; 4],
) {
    // The dividend is equal to i32::MIN = 0x8000_0000
    // i32::MIN % M31 = 1
    constrain_equal(
        eval,
        selector.clone() * is_overflow.clone(),
        dividend[0].clone()
            + dividend[1].clone() * BaseField::from(1 << 8)
            + dividend[2].clone() * BaseField::from(1 << 16)
            + dividend[3].clone() * BaseField::from(1 << 24),
        E::F::one(),
    );

    // The divisor is equal to -1
    constrain_equal(
        eval,
        selector.clone() * is_overflow.clone(),
        divisor[0].clone() + divisor[1].clone() * BaseField::from(1 << 8),
        E::F::from(BaseField::from_u32_unchecked(0xFFFF)),
    );

    constrain_equal(
        eval,
        selector * is_overflow,
        divisor[2].clone() + divisor[3].clone() * BaseField::from(1 << 8),
        E::F::from(BaseField::from_u32_unchecked(0xFFFF)),
    );
}

pub(super) fn constrain_values_equal<E: EvalAtRow>(
    eval: &mut E,
    selector: E::F,
    value_a: [E::F; 4],
    value_b: [E::F; 4],
) {
    constrain_equal(
        eval,
        selector.clone(),
        value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8),
        value_b[0].clone() + value_b[1].clone() * BaseField::from(1 << 8),
    );

    constrain_equal(
        eval,
        selector,
        value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8),
        value_b[2].clone() + value_b[3].clone() * BaseField::from(1 << 8),
    );
}
