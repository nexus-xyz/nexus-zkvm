use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_spartan::polycommitments::PolyCommitmentScheme;
use ark_std::fmt::Debug;

use super::NonNativeAffineVar;
use crate::folding::hypernova::cyclefold::nimfs::{CCSInstance, LCCSInstance};

#[must_use]
#[derive(Debug)]
pub struct CCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: NonNativeAffineVar<G1>,
    /// Public input of non-linearized instance.
    pub X: Vec<FpVar<G1::ScalarField>>,

    _commitment_scheme: PhantomData<C1>,
}

impl<G1, C1> Clone for CCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
            _commitment_scheme: self._commitment_scheme,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CCSInstanceFromR1CSVar<G1, C1>(CCSInstanceVar<G1, C1>)
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField;

impl<G1, C1> CCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField
{
    fn var(&self) -> &CCSInstanceVar<G1, C1> {
        &self.0
    }
}

impl<G1, C1> R1CSVar<G1::ScalarField> for CCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    type Value = CCSInstance<G1, C1>;

    fn cs(&self) -> ConstraintSystemRef<G1::ScalarField> {
        self.var()
            .X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.var().commitment_W.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.var().commitment_W.value()?;
        let X = self.var().X.value()?;
        Ok(CCSInstance { commitment_W: vec![commitment_W].into(), X })
    }
}

impl<G1, C1> AllocVar<CCSInstance<G1, C1>, G1::ScalarField> for CCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    fn new_variable<T: Borrow<CCSInstance<G1, C1>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;
        // Only allocate valid instance, which starts with F::ONE.
        assert_eq!(X[0], G1::ScalarField::ONE);

        let commitment_W = NonNativeAffineVar::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W.into()),
            mode,
        )?;
        let alloc_X = X[1..]
            .iter()
            .map(|x| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(x), mode));
        let X = std::iter::once(Ok(FpVar::constant(G1::ScalarField::ONE)))
            .chain(alloc_X)
            .collect::<Result<_, _>>()?;

        Ok(Self(CCSInstanceVar {
            commitment_W,
            X,
            _commitment_scheme: PhantomData,
        }))
    }
}

impl<G1, C1> AbsorbGadget<G1::ScalarField> for CCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G1::ScalarField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        Ok([
            self.var().commitment_W.to_sponge_field_elements()?,
            (&self.var().X[1..]).to_sponge_field_elements()?,
        ]
        .concat())
    }
}

#[must_use]
#[derive(Debug)]
pub struct LCCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: NonNativeAffineVar<G1>,
    /// Public input of linearized instance. Expected to start with `u`.
    pub X: Vec<FpVar<G1::ScalarField>>,
    /// Random evaluation point of linearized instance.
    pub rs: Vec<FpVar<G1::ScalarField>>,
    /// Target evaluations for linearized instance.
    pub vs: Vec<FpVar<G1::ScalarField>>,

    _commitment_scheme: PhantomData<C1>,
}

impl<G1, C1> Clone for LCCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
            rs: self.rs.clone(),
            vs: self.vs.clone(),
            _commitment_scheme: self._commitment_scheme,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LCCSInstanceFromR1CSVar<G1, C1>(LCCSInstanceVar<G1, C1>)
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField;

impl<G1, C1> LCCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    pub(super) fn new(
        commitment_W: NonNativeAffineVar<G1>,
        X: Vec<FpVar<G1::ScalarField>>,
        rs: Vec<FpVar<G1::ScalarField>>,
        vs: Vec<FpVar<G1::ScalarField>>,
    ) -> Self {
        Self(LCCSInstanceVar{
            commitment_W,
            X,
            rs,
            vs,
            _commitment_scheme: PhantomData,
        })
    }

    fn var(&self) -> &LCCSInstanceVar<G1, C1> {
        &self.0
    }
}

impl<G1, C1> R1CSVar<G1::ScalarField> for LCCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    type Value = LCCSInstance<G1, C1>;

    fn cs(&self) -> ConstraintSystemRef<G1::ScalarField> {
        self.var()
            .X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.var().commitment_W.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.var().commitment_W.value()?;

        let X = self.var().X.value()?;
        let rs = self.var().rs.value()?;
        let vs = self.var().vs.value()?;
        Ok(LCCSInstance {
            commitment_W: vec![commitment_W].into(),
            X,
            rs,
            vs,
        })
    }
}

impl<G1, C1> AllocVar<LCCSInstance<G1, C1>, G1::ScalarField> for LCCSInstanceFromR1CSVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    fn new_variable<T: Borrow<LCCSInstance<G1, C1>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;
        let rs = &r1cs.borrow().rs;
        let vs = &r1cs.borrow().vs;

        let commitment_W = NonNativeAffineVar::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W.into()),
            mode,
        )?;

        let X = X
            .iter()
            .map(|x| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(x), mode))
            .collect::<Result<_, _>>()?;

        let rs = rs
            .iter()
            .map(|r| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(r), mode))
            .collect::<Result<_, _>>()?;

        let vs = vs
            .iter()
            .map(|v| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(v), mode))
            .collect::<Result<_, _>>()?;

        Ok(Self(LCCSInstanceVar {
            commitment_W,
            X,
            rs,
            vs,
            _commitment_scheme: PhantomData,
        }))
    }
}

impl<G1, C1> AbsorbGadget<G1::ScalarField> for LCCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G1::ScalarField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            self.X.to_sponge_field_elements()?,
            self.rs.to_sponge_field_elements()?,
            self.vs.to_sponge_field_elements()?,
        ]
        .concat())
    }
}

impl<G1, C1> CondSelectGadget<G1::ScalarField> for LCCSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: PolyCommitmentScheme<Projective<G1>>,
{
    fn conditionally_select(
        cond: &Boolean<G1::ScalarField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let commitment_W = cond.select(&true_value.commitment_W, &false_value.commitment_W)?;

        let X = true_value
            .X
            .iter()
            .zip(&false_value.X)
            .map(|(x1, x2)| cond.select(x1, x2))
            .collect::<Result<_, _>>()?;

        let rs = true_value
            .rs
            .iter()
            .zip(&false_value.rs)
            .map(|(x1, x2)| cond.select(x1, x2))
            .collect::<Result<_, _>>()?;

        let vs = true_value
            .vs
            .iter()
            .zip(&false_value.vs)
            .map(|(x1, x2)| cond.select(x1, x2))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            X,
            rs,
            vs,
            _commitment_scheme: PhantomData,
        })
    }
}
