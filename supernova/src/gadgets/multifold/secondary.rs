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
    groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    select::CondSelectGadget,
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use super::{cast_field_element_unique, NonNativeAffineVar};
use crate::{
    commitment::CommitmentScheme,
    gadgets::nonnative::AllocVarExt,
    multifold::{
        self,
        nimfs::{R1CSInstance, RelaxedR1CSInstance},
        secondary::{Circuit as SecondaryCircuit, Proof, SecondaryCircuit as _},
    },
};

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
            .map(|x| NonNativeFieldVar::new_variable_unconstrained(cs.clone(), || Ok(x), mode));

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
                NonNativeFieldVar::<G2::ScalarField, G2::BaseField>::new_variable_unconstrained(
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
            folding::R1CSInstanceVar<'_, G2, C2>,
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
            commitment_W += U.commitment_W().scalar_mul_le(r_bits.iter())?;
            commitment_E += commitment_T.scalar_mul_le(r_bits.iter())?;

            for (x1, x2) in X.iter_mut().zip(U.X()) {
                *x1 += x2.mul_without_reduce(r)?;
            }

            if let folding::R1CSInstanceVar::Relaxed(U) = U {
                let r_square_bits = r.square()?.to_bits_le()?;
                commitment_E += U.commitment_E.scalar_mul_le(r_square_bits.iter())?;
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
    pub(crate) U: R1CSInstanceVar<G2, C2>,
    pub(crate) commitment_T: ProjectiveVar<G2, FpVar<G2::BaseField>>,
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

impl<G2, C2> ProofVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    /// Allocate new variable, cloning part of the public input of `U` from provided
    /// `g1` and `g2`.
    ///
    /// Used by the Nova augmented circuit to avoid enforcing equality on witnesses.
    pub fn from_allocated_input<G1>(
        g1: &NonNativeAffineVar<G1>,
        g2: &NonNativeAffineVar<G1>,
        proof: &multifold::secondary::Proof<G2, C2>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let cs = g1.cs().or(g2.cs());

        let mut X = vec![NonNativeFieldVar::one()];
        X.append(&mut g1.into_projective()?);
        X.append(&mut g2.into_projective()?);

        // Allocate g_out and r.
        let mut g_out: Vec<NonNativeFieldVar<_, _>> = proof.U.X[7..10]
            .iter()
            .map(|x| NonNativeFieldVar::new_variable_unconstrained(cs.clone(), || Ok(x), mode))
            .collect::<Result<_, _>>()?;
        let r = NonNativeFieldVar::new_variable_unconstrained(
            cs.clone(),
            || Ok(&proof.U.X[multifold::secondary::Circuit::<G1>::NUM_IO - 1]),
            mode,
        )?;
        X.append(&mut g_out);
        X.push(r);

        let commitment_W = ProjectiveVar::<G2, FpVar<G2::BaseField>>::new_variable(
            cs.clone(),
            || Ok(proof.U.commitment_W),
            mode,
        )?;
        let U = R1CSInstanceVar {
            commitment_W,
            X,
            _commitment_scheme: PhantomData,
        };
        let commitment_T = <ProjectiveVar<G2, FpVar<G2::BaseField>> as AllocVar<
            C2::Commitment,
            G2::BaseField,
        >>::new_variable(cs.clone(), || Ok(&proof.commitment_T), mode)?;
        Ok(Self { U, commitment_T })
    }
}

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

impl<G2, C2> R1CSInstanceVar<G2, C2>
where
    G2: SWCurveConfig,
    G2::BaseField: PrimeField,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    /// Parses `r, g_out` from the public input of the secondary circuit.
    pub fn parse_secondary_io<G1>(
        &self,
    ) -> Result<
        (
            NonNativeFieldVar<G1::BaseField, G1::ScalarField>,
            NonNativeAffineVar<G1>,
        ),
        SynthesisError,
    >
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let r = self.X[SecondaryCircuit::<G1>::NUM_IO - 1].clone();

        // Skip `Variable::One`, g1 and g2.
        let mut X = &self.X[7..];
        let g_out = parse_projective!(X);

        let _ = X;

        Ok((r, g_out))
    }

    /// Parses `[g1, g2, g3, g_out], r` from the public input of the secondary circuit.
    pub fn parse_relaxed_secondary_io<G1>(
        &self,
    ) -> Result<
        (
            [NonNativeAffineVar<G1>; 4],
            NonNativeFieldVar<G1::BaseField, G1::ScalarField>,
        ),
        SynthesisError,
    >
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    {
        let mut X = &self.X[1..];

        let g1 = parse_projective!(X);
        let g2 = parse_projective!(X);
        let g_out = parse_projective!(X);

        let r = X.get(0).ok_or(SynthesisError::Unsatisfiable)?.clone();

        let mut X = &X[1..];
        let g3 = parse_projective!(X);
        let _ = X;

        Ok(([g1, g2, g3, g_out], r))
    }
}

pub(super) mod folding {
    use crate::commitment::CommitmentScheme;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_ff::PrimeField;
    use ark_r1cs_std::{
        fields::{fp::FpVar, nonnative::NonNativeFieldVar},
        groups::curves::short_weierstrass::ProjectiveVar,
    };

    #[must_use]
    pub enum R1CSInstanceVar<'a, G2, C2>
    where
        G2: SWCurveConfig,
        G2::BaseField: PrimeField,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    {
        Strict(&'a super::R1CSInstanceVar<G2, C2>),
        Relaxed(&'a super::RelaxedR1CSInstanceVar<G2, C2>),
    }

    impl<'a, G2, C2> From<&'a super::R1CSInstanceVar<G2, C2>> for R1CSInstanceVar<'a, G2, C2>
    where
        G2: SWCurveConfig,
        G2::BaseField: PrimeField,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    {
        fn from(u: &'a super::R1CSInstanceVar<G2, C2>) -> Self {
            Self::Strict(u)
        }
    }

    impl<'a, G2, C2> From<&'a super::RelaxedR1CSInstanceVar<G2, C2>> for R1CSInstanceVar<'a, G2, C2>
    where
        G2: SWCurveConfig,
        G2::BaseField: PrimeField,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    {
        fn from(U: &'a super::RelaxedR1CSInstanceVar<G2, C2>) -> Self {
            Self::Relaxed(U)
        }
    }

    impl<G2, C2> R1CSInstanceVar<'_, G2, C2>
    where
        G2: SWCurveConfig,
        G2::BaseField: PrimeField,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    {
        pub fn X(&self) -> &[NonNativeFieldVar<G2::ScalarField, G2::BaseField>] {
            match self {
                R1CSInstanceVar::Strict(u) => &u.X,
                R1CSInstanceVar::Relaxed(U) => &U.X,
            }
        }

        pub fn commitment_W(&self) -> &ProjectiveVar<G2, FpVar<G2::BaseField>> {
            match self {
                R1CSInstanceVar::Strict(u) => &u.commitment_W,
                R1CSInstanceVar::Relaxed(U) => &U.commitment_W,
            }
        }
    }
}
