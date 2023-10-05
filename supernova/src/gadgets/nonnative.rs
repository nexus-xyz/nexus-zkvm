use std::borrow::Borrow;

use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, nonnative::NonNativeFieldVar},
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::Zero;

use super::multifold::cast_field_element_unique;

#[must_use]
#[derive(Debug)]
pub struct NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    pub x: NonNativeFieldVar<G1::BaseField, G1::ScalarField>,
    pub y: NonNativeFieldVar<G1::BaseField, G1::ScalarField>,
    pub infinity: Boolean<G1::ScalarField>,
}

impl<G1> Clone for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            infinity: self.infinity.clone(),
        }
    }
}

impl<G1> R1CSVar<G1::ScalarField> for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    type Value = Projective<G1>;

    fn cs(&self) -> ConstraintSystemRef<G1::ScalarField> {
        self.x.cs().or(self.y.cs()).or(self.infinity.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(if self.infinity.value()? {
            Projective::zero()
        } else {
            Projective {
                x: self.x.value()?,
                y: self.y.value()?,
                z: G1::BaseField::ONE,
            }
        })
    }
}

impl<G1> AllocVar<Projective<G1>, G1::ScalarField> for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn new_variable<T: Borrow<Projective<G1>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let g = f()?;

        let affine = g.borrow().into_affine();

        let x = NonNativeFieldVar::new_variable(cs.clone(), || Ok(affine.x), mode)?;
        let y = NonNativeFieldVar::new_variable(cs.clone(), || Ok(affine.y), mode)?;
        let infinity = Boolean::new_variable(cs.clone(), || Ok(affine.infinity), mode)?;

        Ok(Self { x, y, infinity })
    }
}

impl<G1> AbsorbGadget<G1::ScalarField> for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G1::ScalarField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        let infinity = FpVar::from(self.infinity.clone());

        Ok([
            &cast_field_element_unique(&self.x)?[..],
            &cast_field_element_unique(&self.y)?[..],
            &[infinity],
        ]
        .concat())
    }
}

impl<G1> EqGadget<G1::ScalarField> for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<G1::ScalarField>, SynthesisError> {
        let x_equal = reduced::is_eq(&self.x, &other.x)?;
        let y_equal = reduced::is_eq(&self.y, &other.y)?;
        let inf_equal = self.infinity.is_eq(&other.infinity)?;

        let coordinates_equal = x_equal.and(&y_equal)?.and(&inf_equal)?;
        let both_are_zero = self.infinity.and(&other.infinity)?;

        both_are_zero.or(&coordinates_equal)
    }
}

impl<G1> CondSelectGadget<G1::ScalarField> for NonNativeAffineVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn conditionally_select(
        cond: &Boolean<G1::ScalarField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let x = cond.select(&true_value.x, &false_value.x)?;
        let y = cond.select(&true_value.y, &false_value.y)?;
        let infinity = cond.select(&true_value.infinity, &false_value.infinity)?;

        Ok(Self { x, y, infinity })
    }
}

mod reduced {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{
        boolean::Boolean,
        eq::EqGadget,
        fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::SynthesisError;

    pub(super) fn is_eq<TargetField, BaseField>(
        a: &NonNativeFieldVar<TargetField, BaseField>,
        b: &NonNativeFieldVar<TargetField, BaseField>,
    ) -> Result<Boolean<BaseField>, SynthesisError>
    where
        TargetField: PrimeField,
        BaseField: PrimeField,
    {
        if let (NonNativeFieldVar::Constant(const_a), NonNativeFieldVar::Constant(const_b)) = (a, b)
        {
            return Ok(Boolean::Constant(const_a == const_b));
        }

        let cs = a.cs().or(b.cs());

        let a = match a {
            NonNativeFieldVar::Constant(c) => AllocatedNonNativeFieldVar::constant(cs.clone(), *c)?,
            NonNativeFieldVar::Var(v) => v.clone(),
        };
        let b = match b {
            NonNativeFieldVar::Constant(c) => AllocatedNonNativeFieldVar::constant(cs.clone(), *c)?,
            NonNativeFieldVar::Var(v) => v.clone(),
        };

        assert_eq!(a.limbs.len(), b.limbs.len());
        let mut result = Boolean::TRUE;
        for (x, y) in a.limbs.iter().zip(&b.limbs) {
            result = result.and(&x.is_eq(y)?)?;
        }

        Ok(result)
    }
}
