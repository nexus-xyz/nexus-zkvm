use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use ff::{FromUniformBytes, PrimeField as FfPrimeField};

#[derive(Debug)]
pub enum FieldConversionError {
    ModulusWrongSize,
    ModulusMismatch,
    #[cfg(test)]
    ValueMismatch,
}

/// Converts an arkworks prime field element to a ff prime field element, generically in the
/// fields. The const parameter `N` is specified by the impl of `ff::FromUniformBytes` for the
/// struct implementing `ff::PrimeField`. For the fields in `halo2curves::grumpkin`, this is `64`.
/// This function returns an error if the moduli of the two fields do not match.
#[allow(dead_code)]
pub fn ark_to_ff<AF, FF, const N: usize>(x: AF) -> Result<FF, FieldConversionError>
where
    AF: ArkPrimeField,
    FF: FfPrimeField + FromUniformBytes<N>,
{
    // check that the size of the moduli for the two fields match
    if AF::MODULUS_BIT_SIZE != FF::NUM_BITS {
        return Err(FieldConversionError::ModulusWrongSize);
    }

    // check that the moduli for the two fields match
    let ark_modulus_bytes = AF::MODULUS.to_bytes_be();
    // this is a bit of an ugly hack, but the ff PrimeField trait only provides a
    // string representation of the modulus. This might not work for all fields,
    // but it works for the grumpkin fields.
    if format!("0x{}", hex::encode(ark_modulus_bytes)) != FF::MODULUS {
        return Err(FieldConversionError::ModulusMismatch);
    }

    // ff requires N to be larger than the number of bytes in the modulus + 16,
    // so the above check should ensure this does not fail
    let mut le_bytes = [0u8; N];
    let x_le_bytes = x.into_bigint().to_bytes_le();
    // this should never fail, since we already checked that the modulus bit sizes match,
    // and `ff::FromUniformBytes`` requires N to be larger than the number of bytes in the modulus.
    assert!(x_le_bytes.len() <= N);
    le_bytes[..x_le_bytes.len()].copy_from_slice(&x_le_bytes);

    Ok(FF::from_uniform_bytes(&le_bytes))
}

#[cfg(test)]
mod tests {
    use ark_grumpkin::{Fq as ArkFq, Fr as ArkFr};
    use ark_std::test_rng;
    use halo2curves::grumpkin::Fr as FfFr;
    use rand_core::RngCore;

    use super::*;

    fn field_conversion_test_helper<AF, FF, const N: usize>() -> Result<(), FieldConversionError>
    where
        AF: ArkPrimeField,
        FF: FfPrimeField + FromUniformBytes<N>,
    {
        let mut rng = test_rng();
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        let x_ark = AF::from_le_bytes_mod_order(bytes.as_slice());
        let x_ff = FF::from_uniform_bytes(&bytes);
        let x_conv = ark_to_ff::<AF, FF, N>(x_ark)?;
        if x_ff != x_conv {
            return Err(FieldConversionError::ValueMismatch);
        }
        Ok(())
    }

    #[test]
    fn field_conversion_test() {
        field_conversion_test_helper::<ArkFr, FfFr, 64>().unwrap();
    }

    #[test]
    fn field_conversion_test_wrong_modulus() {
        field_conversion_test_helper::<ArkFq, FfFr, 64>().unwrap_err();
    }
}
