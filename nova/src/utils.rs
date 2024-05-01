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

/// An implementation of base_2 log that will never fail, instead returning 0 for all values smaller than 1.
/// It is 'safe' in the sense that it will not panic, unlike just calling `.unwrap()` on a `.checked_ilog2`.
/// Usually used to compute the number of bits needed to index a set or a vector.
#[macro_export]
macro_rules! safe_log {
    ($x:expr) => {
        match $x {
            x if x <= 1 => 0,
            x if x > 1 => $x.saturating_sub(1).checked_ilog2().unwrap_or(0) + 1,
            _ => unreachable!(),
        }
    };
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

    #[test]
    fn safe_log() {
        assert_eq!(safe_log!(i32::MIN), 0);
        assert_eq!(safe_log!(-8i32), 0);
        assert_eq!(safe_log!(-1i32), 0);
        assert_eq!(safe_log!(0u32), 0);
        assert_eq!(safe_log!(1u32), 0);
        assert_eq!(safe_log!(8u32), 3);
        assert_eq!(safe_log!(u32::MAX), 32);
    }
}
