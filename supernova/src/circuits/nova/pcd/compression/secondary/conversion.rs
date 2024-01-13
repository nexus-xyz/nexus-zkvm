use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use ark_std::One;
use ff::{FromUniformBytes, PrimeField as FfPrimeField};
use halo2_proofs::halo2curves::CurveAffine;

#[derive(Debug)]
pub enum FieldConversionError {
    ModulusWrongSize,
    ModulusMismatch,
    #[cfg(test)]
    ValueMismatch,
}

#[derive(Debug)]
pub enum GroupConversionError {
    EquationMismatch,
    BaseFieldMismatch,
    ScalarFieldMismatch,
    PointAtInfinity,
}

#[derive(Debug)]
pub enum ConversionError {
    Field(FieldConversionError),
    Group(GroupConversionError),
}

impl From<FieldConversionError> for ConversionError {
    fn from(e: FieldConversionError) -> Self {
        ConversionError::Field(e)
    }
}
impl From<GroupConversionError> for ConversionError {
    fn from(e: GroupConversionError) -> Self {
        ConversionError::Group(e)
    }
}

/// converts an arkworks prime field element to a ff prime field element, generically in the
/// fields. The const parameter `N` is specified by the impl of `ff::FromUniformBytes` for the
/// struct implementing `ff::PrimeField`. For the fields in `halo2curves::grumpkin`, this is `64`.
/// This function returns an error if the moduli of the two fields do not match.
pub fn ark_to_ff_field<AF, FF, const N: usize>(x: AF) -> Result<FF, FieldConversionError>
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

/// converts a point of an arkworks short weierstrass curve to one on the corresponding halo2 curve.
/// note that the `CurveAffine` trait from `halo2curves` is for short weierstrass curves only.
/// this only works when the base field is a prime field.
/// returns an error if the curves have different equations, different base fields,
/// or different scalar fields/cofactors, or if the point is the point at infinity.
#[allow(dead_code)]
pub fn ark_to_halo2_group<AG, HG, const N: usize>(p: Affine<AG>) -> Result<HG, GroupConversionError>
where
    HG: CurveAffine,
    AG: SWCurveConfig,
    AG::BaseField: ArkPrimeField,
    HG::Base: FfPrimeField + FromUniformBytes<N>,
    HG::Scalar: FromUniformBytes<N>,
{
    let a = AG::COEFF_A;
    let b = AG::COEFF_B;

    // verify that the base fields match
    let (a_ff, b_ff) = {
        let a_ff = ark_to_ff_field::<AG::BaseField, HG::Base, N>(a)
            .map_err(|_| GroupConversionError::BaseFieldMismatch)?;
        let b_ff = ark_to_ff_field::<AG::BaseField, HG::Base, N>(b)
            .map_err(|_| GroupConversionError::BaseFieldMismatch)?;
        (a_ff, b_ff)
    };
    // verify that the curve equations match
    if a_ff != HG::a() || b_ff != HG::b() {
        return Err(GroupConversionError::EquationMismatch);
    }
    // verify that the scalar fields match
    ark_to_ff_field::<AG::ScalarField, HG::ScalarExt, N>(AG::ScalarField::one())
        .map_err(|_| GroupConversionError::ScalarFieldMismatch)?;

    let (x, y) = p.xy().ok_or(GroupConversionError::PointAtInfinity)?;
    let x_ff = ark_to_ff_field::<AG::BaseField, HG::Base, N>(x)
        .map_err(|_| GroupConversionError::BaseFieldMismatch)?;
    let y_ff = ark_to_ff_field::<AG::BaseField, HG::Base, N>(y)
        .map_err(|_| GroupConversionError::BaseFieldMismatch)?;

    // the above checks should be sufficient to ensure that the point is on the curve
    Ok(HG::from_xy(x_ff, y_ff).expect("point should be on curve"))
}
#[cfg(test)]
mod tests {
    use ark_ec::CurveGroup;
    use ark_grumpkin::{Fq as ArkFq, Fr as ArkFr, GrumpkinConfig as ArkGrumpkin};
    use ark_std::{test_rng, UniformRand};
    use halo2curves::{
        group::Curve,
        grumpkin::{Fr as FfFr, G1Affine as HaloGrumpkin},
    };
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
        let x_conv = ark_to_ff_field::<AF, FF, N>(x_ark)?;
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

    // tests conversion of points by checking that conversion commutes with curve addition.
    fn group_conversion_test_helper<AG, HG, const N: usize>()
    where
        HG: CurveAffine,
        AG: SWCurveConfig,
        AG::BaseField: ArkPrimeField,
        HG::Base: FfPrimeField + FromUniformBytes<N>,
        HG::ScalarExt: FromUniformBytes<N>,
    {
        let mut rng = test_rng();
        let p_ark = Affine::<AG>::rand(&mut rng);
        let q_ark = Affine::<AG>::rand(&mut rng);
        let sum_ark = (p_ark + q_ark).into_affine();
        let p_ff = ark_to_halo2_group::<AG, HG, N>(p_ark).unwrap();
        let q_ff = ark_to_halo2_group::<AG, HG, N>(q_ark).unwrap();
        let sum_ff = (p_ff + q_ff).to_affine();
        let sum_conv = ark_to_halo2_group::<AG, HG, N>(sum_ark).unwrap();
        assert_eq!(sum_ff, sum_conv);
    }

    #[test]
    fn group_conversion_test() {
        group_conversion_test_helper::<ArkGrumpkin, HaloGrumpkin, 64>();
    }
}
