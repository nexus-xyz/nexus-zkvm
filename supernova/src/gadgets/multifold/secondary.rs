use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::sponge::constraints::AbsorbGadget;
use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    fields::{
        fp::FpVar,
        nonnative::{NonNativeFieldMulResultVar, NonNativeFieldVar},
        FieldVar,
    },
    groups::curves::short_weierstrass::ProjectiveVar,
    groups::CurveVar,
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use super::{cast_field_element_unique, NonNativeAffineVar};
use crate::{
    commitment::CommitmentScheme,
    multifold::{
        nimfs::{R1CSInstance, RelaxedR1CSInstance},
        secondary::Proof,
    },
};

/// Public input of secondary circuit.
pub struct PubIoVar<G1>
where
    G1: SWCurveConfig,
    G1::BaseField: PrimeField,
{
    pub g1: NonNativeAffineVar<G1>,
    pub g2: NonNativeAffineVar<G1>,
    pub g_out: NonNativeAffineVar<G1>,
    pub r: NonNativeFieldVar<G1::BaseField, G1::ScalarField>,
}

#[must_use]
#[derive(Debug)]
pub struct R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: ProjectiveVar<G2, FpVar<G2::BaseField>>,
    /// Public input of non-relaxed instance.
    pub X: Vec<NonNativeFieldVar<G2::ScalarField, G2::BaseField>>,

    _commitment_scheme: PhantomData<C2>,
}

impl<G2, C2> Clone for R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
{
    fn clone(&self) -> Self {
        Self {
            commitment_W: self.commitment_W.clone(),
            X: self.X.clone(),
            _commitment_scheme: self._commitment_scheme,
        }
    }
}

impl<G2, C2> R1CSVar<G2::BaseField> for R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    type Value = R1CSInstance<G2, C2>;

    fn cs(&self) -> ConstraintSystemRef<G2::BaseField> {
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

impl<G2, C2> AllocVar<R1CSInstance<G2, C2>, G2::BaseField> for R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn new_variable<T: Borrow<R1CSInstance<G2, C2>>>(
        cs: impl Into<Namespace<G2::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;
        // Only allocate valid instance, which starts with F::ONE.
        assert_eq!(X[0], G2::ScalarField::ONE);

        let commitment_W = ProjectiveVar::<G2, FpVar<G2::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W),
            mode,
        )?;
        let alloc_X = X[1..]
            .iter()
            .map(|x| NonNativeFieldVar::new_variable(cs.clone(), || Ok(x), mode));

        let X = std::iter::once(Ok(NonNativeFieldVar::constant(G2::ScalarField::ONE)))
            .chain(alloc_X)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<G2, C2> AbsorbGadget<G2::BaseField> for R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G2::BaseField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G2::BaseField>>, SynthesisError> {
        let X = self
            .X
            .iter()
            .skip(1)
            .map(cast_field_element_unique)
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        Ok([self.commitment_W.to_sponge_field_elements()?, X].concat())
    }
}

#[must_use]
#[derive(Debug)]
pub struct RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: ProjectiveVar<G2, FpVar<G2::BaseField>>,
    /// Commitment to error vector.
    pub commitment_E: ProjectiveVar<G2, FpVar<G2::BaseField>>,
    /// Public input of relaxed instance.
    pub X: Vec<NonNativeFieldVar<G2::ScalarField, G2::BaseField>>,

    _commitment_scheme: PhantomData<C2>,
}

impl<G2, C2> Clone for RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
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

impl<G2, C2> R1CSVar<G2::BaseField> for RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    type Value = RelaxedR1CSInstance<G2, C2>;

    fn cs(&self) -> ConstraintSystemRef<G2::BaseField> {
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

impl<G2, C2> AllocVar<RelaxedR1CSInstance<G2, C2>, G2::BaseField> for RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn new_variable<T: Borrow<RelaxedR1CSInstance<G2, C2>>>(
        cs: impl Into<Namespace<G2::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;

        let commitment_W = ProjectiveVar::<G2, FpVar<G2::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W),
            mode,
        )?;
        let commitment_E = ProjectiveVar::<G2, FpVar<G2::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_E),
            mode,
        )?;

        let X = X
            .iter()
            .map(|x| {
                NonNativeFieldVar::<G2::ScalarField, G2::BaseField>::new_variable(
                    cs.clone(),
                    || Ok(x),
                    mode,
                )
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<G2, C2> AbsorbGadget<G2::BaseField> for RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<G2::BaseField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<G2::BaseField>>, SynthesisError> {
        let X = self
            .X
            .iter()
            .map(cast_field_element_unique)
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            self.commitment_E.to_sponge_field_elements()?,
            X,
        ]
        .concat())
    }
}

impl<G2, C2> CondSelectGadget<G2::BaseField> for RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn conditionally_select(
        cond: &Boolean<G2::BaseField>,
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

impl<G2, C2> RelaxedR1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    pub(super) fn fold(
        &self,
        instances: &[(
            &'_ R1CSInstanceVar<G2, C2>,
            &'_ ProjectiveVar<G2, FpVar<G2::BaseField>>,
            &'_ NonNativeFieldVar<G2::ScalarField, G2::BaseField>,
            &'_ [Boolean<G2::BaseField>],
        )],
    ) -> Result<Self, SynthesisError> {
        let mut commitment_W = self.commitment_W.clone();
        let mut commitment_E = self.commitment_E.clone();
        let mut X: Vec<NonNativeFieldMulResultVar<_, _>> = self
            .X
            .iter()
            .map(NonNativeFieldMulResultVar::from)
            .collect();

        for (U, commitment_T, r, r_bits) in instances {
            commitment_W += U.commitment_W.scalar_mul_le(r_bits.iter())?;
            commitment_E += commitment_T.scalar_mul_le(r_bits.iter())?;

            for (x1, x2) in X.iter_mut().zip(&U.X) {
                *x1 += x2.mul_without_reduce(r)?;
            }
        }

        let X = X
            .iter()
            .map(NonNativeFieldMulResultVar::reduce)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            commitment_W,
            commitment_E,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

pub struct ProofVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    pub(super) U: R1CSInstanceVar<G2, C2>,
    pub(super) commitment_T: ProjectiveVar<G2, FpVar<G2::BaseField>>,
}

impl<G2, C2> AllocVar<Proof<G2, C2>, G2::BaseField> for ProofVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn new_variable<T: Borrow<Proof<G2, C2>>>(
        cs: impl Into<Namespace<G2::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof = f()?;

        Ok(Self {
            U: R1CSInstanceVar::new_variable(cs.clone(), || Ok(&proof.borrow().U), mode)?,
            commitment_T: <ProjectiveVar<G2, FpVar<G2::BaseField>> as AllocVar<
                C2::Commitment,
                G2::BaseField,
            >>::new_variable(
                cs.clone(), || Ok(&proof.borrow().commitment_T), mode
            )?,
        })
    }
}

impl<G2, C2> R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    pub fn parse_io<G1>(&self) -> Result<PubIoVar<G1>, SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        macro_rules! parse_projective {
            ($X:ident) => {
                match &$X[..3] {
                    [x, y, z, ..] => {
                        let zero = Affine::<G1>::zero();
                        let zero_x = NonNativeFieldVar::constant(zero.x);
                        let zero_y = NonNativeFieldVar::constant(zero.y);
                        let infinity = z.is_zero()?;

                        let x = infinity.select(&zero_x, x)?;
                        let y = infinity.select(&zero_y, y)?;

                        let point = NonNativeAffineVar { x, y, infinity };
                        $X = &$X[3..];
                        point
                    }
                    _ => return Err(SynthesisError::Unsatisfiable),
                }
            };
        }

        let mut X = &self.X[1..];

        let g1 = parse_projective!(X);
        let g2 = parse_projective!(X);
        let g_out = parse_projective!(X);

        let r = X.get(0).ok_or(SynthesisError::Unsatisfiable)?.clone();

        Ok(PubIoVar { g1, g2, g_out, r })
    }
}
