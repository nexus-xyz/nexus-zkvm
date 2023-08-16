//! Committed relaxed R1CS in-circuit implementation.

use std::{fmt, marker::PhantomData};

use ark_crypto_primitives::sponge::{
    constraints::{AbsorbGadget, CryptographicSpongeVar},
    CryptographicSponge,
};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::{fp::FpVar, nonnative::NonNativeFieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    prelude::{CurveVar, FieldVar},
    uint8::UInt8,
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::{commitment::CommitmentScheme, nifs::SQUEEZE_ELEMENTS_BIT_SIZE, r1cs};

type R1CSInstance<C, S> = r1cs::R1CSInstance<Projective<C>, S>;
type RelaxedR1CSInstance<C, S> = r1cs::RelaxedR1CSInstance<Projective<C>, S>;

/// Reinterprets bytes of `F1` element as `F2` element, wrapping around the modulus.
///
/// This is unsafe since it can lead to non-unique element representation.
unsafe fn cast_field_element<F1, F2>(element: &F1) -> F2
where
    F1: PrimeField,
    F2: PrimeField,
{
    F2::from_le_bytes_mod_order(&element.into_bigint().to_bytes_le())
}

/// Mirror of [`scalar_to_base`](crate::utils::scalar_to_base) for allocated input.
pub fn scalar_to_base<C>(
    scalar: &NonNativeFieldVar<C::ScalarField, C::BaseField>,
) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
{
    scalar.to_bytes()?.to_constraint_field()
}

#[must_use]
#[derive(Debug, Clone)]
pub struct R1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: ProjectiveVar<C, FpVar<C::BaseField>>,
    /// Public input of non-relaxed instance. Each element is assumed to be limited by [`SQUEEZE_ELEMENTS_BIT_SIZE`].
    pub X: Vec<FpVar<C::BaseField>>,

    _commitment_scheme: PhantomData<S>,
}

impl<C, S> R1CSVar<C::BaseField> for R1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
    S: CommitmentScheme<Projective<C>, Commitment = Projective<C>> + Clone + Eq + fmt::Debug,
{
    type Value = R1CSInstance<C, S>;

    fn cs(&self) -> ConstraintSystemRef<C::BaseField> {
        self.X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.commitment_W.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.commitment_W.value()?;
        let X: Vec<C::ScalarField> = self
            .X
            .iter()
            .map(|x| Ok(unsafe { cast_field_element(&x.value()?) }))
            .collect::<Result<_, _>>()?;

        Ok(R1CSInstance { commitment_W, X })
    }
}

impl<C, S> AllocVar<R1CSInstance<C, S>, C::BaseField> for R1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
    S: CommitmentScheme<Projective<C>, Commitment = Projective<C>>,
{
    fn new_variable<T: std::borrow::Borrow<R1CSInstance<C, S>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;
        // Only allocate valid instance, which starts with F::ONE.
        assert_eq!(X[0], C::ScalarField::ONE);

        let commitment_W = ProjectiveVar::<C, FpVar<C::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W),
            mode,
        )?;
        let alloc_X = X[1..].iter().map(|x| {
            FpVar::<C::BaseField>::new_variable(
                cs.clone(),
                || Ok(unsafe { cast_field_element::<C::ScalarField, C::BaseField>(x) }),
                mode,
            )
        });
        let X = std::iter::once(Ok(FpVar::constant(C::BaseField::ONE)))
            .chain(alloc_X)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<C, S> AbsorbGadget<C::BaseField> for R1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<C::BaseField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            self.X.to_sponge_field_elements()?,
        ]
        .concat())
    }
}

#[must_use]
#[derive(Debug, Clone)]
pub struct RelaxedR1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
{
    /// Commitment to witness.
    pub commitment_W: ProjectiveVar<C, FpVar<C::BaseField>>,
    /// Commitment to error vector.
    pub commitment_E: ProjectiveVar<C, FpVar<C::BaseField>>,
    /// `u` parameter of the relaxed instance. This element is allocated natively because
    /// we only fold with non-relaxed instances, thus there's no multiplication
    /// involved and this variable is also guaranteed to fit into [`SQUEEZE_ELEMENTS_BIT_SIZE`].
    pub u: FpVar<C::BaseField>,
    /// Public input of relaxed instance. There's no guarantee about it being limited
    /// in size because of the folding operation. Hence allocated as non-native.
    pub X: Vec<NonNativeFieldVar<C::ScalarField, C::BaseField>>,

    _commitment_scheme: PhantomData<S>,
}

impl<C, S> R1CSVar<C::BaseField> for RelaxedR1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
    S: CommitmentScheme<Projective<C>, Commitment = Projective<C>> + Clone + Eq + fmt::Debug,
{
    type Value = RelaxedR1CSInstance<C, S>;

    fn cs(&self) -> ConstraintSystemRef<C::BaseField> {
        self.X
            .iter()
            .fold(ConstraintSystemRef::None, |cs, x| cs.or(x.cs()))
            .or(self.u.cs())
            .or(self.commitment_W.cs())
            .or(self.commitment_E.cs())
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let commitment_W = self.commitment_W.value()?;
        let commitment_E = self.commitment_E.value()?;
        let u = unsafe { cast_field_element::<C::BaseField, C::ScalarField>(&self.u.value()?) };
        let mut X: Vec<C::ScalarField> = self
            .X
            .iter()
            .map(NonNativeFieldVar::value)
            .collect::<Result<_, _>>()?;
        X.insert(0, u);
        Ok(RelaxedR1CSInstance {
            commitment_W,
            commitment_E,
            X,
        })
    }
}

impl<C, S> AllocVar<RelaxedR1CSInstance<C, S>, C::BaseField> for RelaxedR1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
    S: CommitmentScheme<Projective<C>, Commitment = Projective<C>>,
{
    fn new_variable<T: std::borrow::Borrow<RelaxedR1CSInstance<C, S>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let r1cs = f()?;
        let X = &r1cs.borrow().X;

        let commitment_W = ProjectiveVar::<C, FpVar<C::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_W),
            mode,
        )?;
        let commitment_E = ProjectiveVar::<C, FpVar<C::BaseField>>::new_variable(
            cs.clone(),
            || Ok(r1cs.borrow().commitment_E),
            mode,
        )?;

        let u = FpVar::new_variable(
            cs.clone(),
            || Ok(unsafe { cast_field_element::<C::ScalarField, C::BaseField>(&X[0]) }),
            mode,
        )?;
        let X = X[1..]
            .iter()
            .map(|x| {
                NonNativeFieldVar::<C::ScalarField, C::BaseField>::new_variable(
                    cs.clone(),
                    || Ok(x),
                    mode,
                )
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            commitment_E,
            u,
            X,
            _commitment_scheme: PhantomData,
        })
    }
}

impl<C, S> AbsorbGadget<C::BaseField> for RelaxedR1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
{
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<C::BaseField>>, SynthesisError> {
        unreachable!()
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        let X = self
            .X
            .iter()
            .map(|x| scalar_to_base::<C>(x))
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        Ok([
            self.commitment_W.to_sponge_field_elements()?,
            self.commitment_E.to_sponge_field_elements()?,
            self.u.to_sponge_field_elements()?,
            X,
        ]
        .concat())
    }
}

impl<C, S> RelaxedR1CSInstanceVar<C, S>
where
    C: SWCurveConfig,
    C::BaseField: PrimeField,
    S: CommitmentScheme<Projective<C>, Commitment = Projective<C>> + Clone + Eq + fmt::Debug,
{
    pub fn fold<ROVar, RO>(
        &self,
        params: &FpVar<C::BaseField>,
        U2: &R1CSInstanceVar<C, S>,
        commitment_T: &ProjectiveVar<C, FpVar<C::BaseField>>,
        config: &ROVar::Parameters,
    ) -> Result<Self, SynthesisError>
    where
        RO: CryptographicSponge,
        ROVar: CryptographicSpongeVar<C::BaseField, RO>,
    {
        let cs = self.cs();
        let mut random_oracle = ROVar::new(cs.clone(), config);

        // Absorb pp_digest.
        random_oracle.absorb(params)?;
        // Absorb U1.
        random_oracle.absorb(self)?;
        // Absorb U2.
        random_oracle.absorb(U2)?;

        // Absorb cross-term commitment.
        random_oracle.absorb(commitment_T)?;

        let (r, bits) = random_oracle
            .squeeze_nonnative_field_elements_with_sizes::<C::ScalarField>(&[
                SQUEEZE_ELEMENTS_BIT_SIZE,
            ])?;

        let r = &r[0];
        let r_bits = &bits[0];

        let commitment_W = &self.commitment_W + U2.commitment_W.scalar_mul_le(r_bits.iter())?;
        let commitment_E = &self.commitment_E + commitment_T.scalar_mul_le(r_bits.iter())?;

        let r_base = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(unsafe { cast_field_element::<C::ScalarField, C::BaseField>(&r.value()?) })
        })?;
        // Public input of U2 starts with F::One, which wasn't allocated.
        let u = &self.u + r_base;

        // SAFETY:
        // r * x2 mod ScalarField::MODULUS = r mod ScalarField::MODULUS * x2 mod ScalarField::MODULUS.
        let X = self
            .X
            .iter()
            .zip(&U2.X[1..])
            .map(|(x1, x2)| {
                let x2 = NonNativeFieldVar::new_witness(cs.clone(), || {
                    Ok(unsafe { cast_field_element::<C::BaseField, C::ScalarField>(&x2.value()?) })
                })?;
                Result::<_, SynthesisError>::Ok(x1 + r * &x2)
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            commitment_W,
            commitment_E,
            X,
            u,
            _commitment_scheme: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        nifs::{tests::synthesize_r1cs, NIFSProof},
        pedersen::PedersenCommitment,
        r1cs,
    };
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};

    use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::Zero;
    use ark_test_curves::bls12_381::{g1::Config, Fq, Fr as Scalar, G1Projective as G};

    #[test]
    fn fold_in_circuit() -> Result<(), SynthesisError> {
        let (ark, mds) =
            find_poseidon_ark_and_mds::<Fq>(Fq::MODULUS.const_num_bits() as u64, 2, 8, 43, 0);
        let config = PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 43,
            alpha: 5,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        };
        const PP_DIGEST: Fq = Fq::ZERO;
        const PP_DIGEST_FR: Scalar = Scalar::ZERO;

        let (shape, U0, W0, pp) = synthesize_r1cs(3, None);
        let (_, U1, W1, _) = synthesize_r1cs(4, Some(&pp));

        let relaxed_U = RelaxedR1CSInstance::<Config, PedersenCommitment<G>>::from(&U0);
        let relaxed_W = r1cs::RelaxedR1CSWitness::from_r1cs_witness(&shape, &W0);
        // Fold once so that there're no zero commitments.
        let (_, (relaxed_U, relaxed_W)) = NIFSProof::<G, _, PoseidonSponge<Fq>>::prove(
            &pp,
            &config,
            &PP_DIGEST_FR,
            &shape,
            &relaxed_U,
            &relaxed_W,
            &U1,
            &W1,
        )
        .unwrap();

        assert_ne!(relaxed_U.commitment_W, G::zero());
        assert_ne!(relaxed_U.commitment_E, G::zero());

        // let relaxed_U = RelaxedR1CSInstance::<Config, PedersenCommitment<G>>::new(&shape);
        // let relaxed_W = r1cs::RelaxedR1CSWitness::zero(&shape);

        let (_, U2, W2, _) = synthesize_r1cs(5, Some(&pp));
        let cs = ConstraintSystem::<Fq>::new_ref();

        // First, fold outside of circuit.
        let (nifs, (_U, folded_W)) = NIFSProof::<G, _, PoseidonSponge<Fq>>::prove(
            &pp,
            &config,
            &PP_DIGEST_FR,
            &shape,
            &relaxed_U,
            &relaxed_W,
            &U2,
            &W2,
        )
        .unwrap();

        assert_ne!(U2.commitment_W, G::zero());
        assert_ne!(nifs.commitment_T, G::zero());

        let relaxed_var = RelaxedR1CSInstanceVar::new_input(cs.clone(), || Ok(relaxed_U))?;
        let var = R1CSInstanceVar::new_input(cs.clone(), || Ok(U2))?;
        let pp_var = FpVar::new_input(cs.clone(), || Ok(PP_DIGEST))?;
        let comm_T_var = ProjectiveVar::new_input(cs.clone(), || Ok(nifs.commitment_T))?;

        let folded =
            relaxed_var.fold::<PoseidonSpongeVar<Fq>, _>(&pp_var, &var, &comm_T_var, &config)?;

        let folded_U = folded.value()?;

        assert_eq!(folded_U, _U);

        shape
            .is_relaxed_satisfied(&folded_U, &folded_W, &pp)
            .unwrap();

        assert!(cs.is_satisfied().unwrap());

        Ok(())
    }
}
