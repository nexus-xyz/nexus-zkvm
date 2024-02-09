use ark_ff::{BigInteger, PrimeField, ToConstraintField};

/// Converts an element of F1 to a vector of elements of the base field. This is a one-to-one encoding.
/// Specifically, the F1 elements is converted to a BigInt in the range [0, p), where p is the order of F1.
/// Then, this integer is 'expanded in base q' to a vector of elements of F2, where q is the order of F2.
pub fn cast_field_element_unique<F1, F2>(element: &F1) -> Vec<F2>
where
    F1: PrimeField,
    F2: PrimeField,
{
    element
        .into_bigint()
        .to_bytes_le()
        .to_field_elements()
        .unwrap()
}

/// Reinterprets bytes of `F1` element as `F2` element, wrapping around the modulus.
///
/// # SAFETY:
///
/// This function is unsafe since it can lead to non-unique element representation.
pub unsafe fn cast_field_element<F1, F2>(element: &F1) -> F2
where
    F1: PrimeField,
    F2: PrimeField,
{
    F2::from_le_bytes_mod_order(&element.into_bigint().to_bytes_le())
}

/// Returns iterator over bits in little-endian order.
pub fn iter_bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| ((1 << bit) & byte) != 0))
}

#[cfg(test)]
mod tests {
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::UniformRand;

    type BigInt = <ark_pallas::Fr as PrimeField>::BigInt;

    #[test]
    fn bits_le() {
        let mut rng = ark_std::test_rng();

        for _ in 0..10 {
            let big_int = BigInt::rand(&mut rng);

            let bytes = big_int.to_bytes_le();
            let bits: Vec<bool> = super::iter_bits_le(&bytes).collect();

            assert_eq!(BigInt::from_bits_le(&bits), big_int);
        }
    }
}
