use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};

/// Converts a scalar to a vector of elements of the base field. This is a one-to-one encoding.
/// Specifically, the scalar is converted to a BigInt in the range [0, p), where p is the order of the scalar field.
/// Then, this integer is 'expanded in base q' to a vector of elements of the base field, where q is the order of the base field.
pub fn scalar_to_base<G>(scalar: &G::ScalarField) -> Vec<G::BaseField>
where
    G: CurveGroup,
    G::BaseField: PrimeField,
{
    scalar
        .into_bigint()
        .to_bytes_le()
        .to_field_elements()
        .unwrap()
}
