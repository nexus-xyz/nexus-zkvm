use ark_ec::{
    short_weirstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{Field as ArkField, PrimeField};
use halo2_proofs::arithmetic::Field as FfField;

pub struct FieldContainer<F: ArkField>(F);

impl<F: ArkField> Into<FieldContainer<F>> for F {
    fn into(self) -> FieldContainer<F> {
        FieldContainer(self)
    }
}

impl<F: ArkField> FfField for FieldConvContainer<F> {
    const ZERO: Self = Self(F::zero());
    const ONE: Self = Self(F::one());

    fn random(rng: impl RngCore) -> Self {
        Self(F::random(rng))
    }

    fn square(&self) -> Self {
        todo!()
    }

    fn double(&self) -> Self {
        todo!()
    }

    fn invert(&self) -> CtOption<Self> {
        todo!()
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        todo!()
    }
    
}
