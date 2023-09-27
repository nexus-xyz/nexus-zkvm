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

use super::NonNativeAffineVar;
use crate::{
    commitment::CommitmentScheme,
    multifold::nimfs::{R1CSInstance, RelaxedR1CSInstance},
};

#[must_use]
#[derive(Debug)]
pub struct R1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: NonNativeAffineVar<G1>,
    /// Public input of non-relaxed instance.
    pub X: Vec<FpVar<G1::ScalarField>>,

    _commitment_scheme: PhantomData<C1>,
}

impl<G1, C1> Clone for R1CSInstanceVar<G1, C1>
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

impl<G1, C1> R1CSVar<G1::ScalarField> for R1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    type Value = R1CSInstance<G1, C1>;

    fn cs(&self) -> ConstraintSystemRef<G1::ScalarField> {
        self.X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.commitment_W.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.commitment_W.value()?;
        let X = self.X.value()?;
        Ok(R1CSInstance { commitment_W, X })
    }
}

impl<G1, C1> AllocVar<R1CSInstance<G1, C1>, G1::ScalarField> for R1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    fn new_variable<T: Borrow<R1CSInstance<G1, C1>>>(
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

        let commitment_W =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(r1cs.borrow().commitment_W), mode)?;
        let alloc_X = X[1..]
            .iter()
            .map(|x| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(x), mode));
        let X = std::iter::once(Ok(FpVar::constant(G1::ScalarField::ONE)))
            .chain(alloc_X)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<G1, C1> AbsorbGadget<G1::ScalarField> for R1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G1::ScalarField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            (&self.X[1..]).to_sponge_field_elements()?,
        ]
        .concat())
    }
}

#[must_use]
#[derive(Debug)]
pub struct RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: NonNativeAffineVar<G1>,
    /// Commitment to error vector.
    pub commitment_E: NonNativeAffineVar<G1>,
    /// Public input of relaxed instance. Expected to start with `u`.
    pub X: Vec<FpVar<G1::ScalarField>>,

    _commitment_scheme: PhantomData<C1>,
}

impl<G1, C1> Clone for RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            commitment_E: self.commitment_E.clone(),
            X: self.X.clone(),
            _commitment_scheme: self._commitment_scheme,
        }
    }
}

impl<G1, C1> RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    pub(super) fn new(
        commitment_W: NonNativeAffineVar<G1>,
        commitment_E: NonNativeAffineVar<G1>,
        X: Vec<FpVar<G1::ScalarField>>,
    ) -> Self {
        Self {
            commitment_W,
            commitment_E,
            X,
            _commitment_scheme: PhantomData,
        }
    }
}

impl<G1, C1> R1CSVar<G1::ScalarField> for RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    type Value = RelaxedR1CSInstance<G1, C1>;

    fn cs(&self) -> ConstraintSystemRef<G1::ScalarField> {
        self.X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.commitment_W.cs())
            .or(self.commitment_E.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.commitment_W.value()?;
        let commitment_E = self.commitment_E.value()?;

        let X = self.X.value()?;
        Ok(RelaxedR1CSInstance {
            commitment_W,
            commitment_E,
            X,
        })
    }
}

impl<G1, C1> AllocVar<RelaxedR1CSInstance<G1, C1>, G1::ScalarField>
    for RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    fn new_variable<T: Borrow<RelaxedR1CSInstance<G1, C1>>>(
        cs: impl Into<Namespace<G1::ScalarField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;

        let commitment_W =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(r1cs.borrow().commitment_W), mode)?;
        let commitment_E =
            NonNativeAffineVar::new_variable(cs.clone(), || Ok(r1cs.borrow().commitment_E), mode)?;

        let X = X
            .iter()
            .map(|x| FpVar::<G1::ScalarField>::new_variable(cs.clone(), || Ok(x), mode))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<G1, C1> AbsorbGadget<G1::ScalarField> for RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G1::ScalarField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError> {
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            self.commitment_E.to_sponge_field_elements()?,
            self.X.to_sponge_field_elements()?,
        ]
        .concat())
    }
}

impl<G1, C1> CondSelectGadget<G1::ScalarField> for RelaxedR1CSInstanceVar<G1, C1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
{
    fn conditionally_select(
        cond: &Boolean<G1::ScalarField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let commitment_W = cond.select(&true_value.commitment_W, &false_value.commitment_W)?;
        let commitment_E = cond.select(&true_value.commitment_E, &false_value.commitment_E)?;

        let X = true_value
            .X
            .iter()
            .zip(&false_value.X)
            .map(|(x1, x2)| cond.select(x1, x2))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}
