use std::marker::PhantomData;

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, ToConstraintField};

use super::{
    absorb::{AbsorbNonNative, CryptographicSpongeExt},
    commitment::{Commitment, CommitmentScheme},
    r1cs::{self, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness},
};

pub const SQUEEZE_ELEMENTS_BIT_SIZE: FieldElementSize = FieldElementSize::Truncated(127);

pub struct NIFSProof<G: CurveGroup, C: CommitmentScheme<G>, RO> {
    pub(crate) commitment_T: C::Commitment,
    _random_oracle: PhantomData<RO>,
}

impl<G: CurveGroup, C: CommitmentScheme<G>, RO> Default for NIFSProof<G, C, RO> {
    fn default() -> Self {
        Self {
            commitment_T: Default::default(),
            _random_oracle: PhantomData,
        }
    }
}

impl<G: CurveGroup, C: CommitmentScheme<G>, RO> Clone for NIFSProof<G, C, RO> {
    fn clone(&self) -> Self {
        Self {
            commitment_T: self.commitment_T,
            _random_oracle: self._random_oracle,
        }
    }
}

impl<G, C, RO> NIFSProof<G, C, RO>
where
    G: CurveGroup + AbsorbNonNative<G::ScalarField>,
    C: CommitmentScheme<G>,
    G::BaseField: PrimeField + Absorb,
    G::ScalarField: Absorb,
    G::Affine: Absorb + ToConstraintField<G::BaseField>,
    RO: CryptographicSponge,
{
    pub fn prove_with_relaxed(
        pp: &C::PP,
        random_oracle: &mut RO,
        shape: &R1CSShape<G>,
        (U1, W1): (&RelaxedR1CSInstance<G, C>, &RelaxedR1CSWitness<G>),
        (U2, W2): (&RelaxedR1CSInstance<G, C>, &RelaxedR1CSWitness<G>),
    ) -> Result<(Self, (RelaxedR1CSInstance<G, C>, RelaxedR1CSWitness<G>)), r1cs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        let (T, commitment_T) = r1cs::commit_T_with_relaxed(shape, pp, U1, W1, U2, W2)?;

        random_oracle.absorb(&commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold_with_relaxed(U2, &commitment_T, &r)?;
        let W = W1.fold_with_relaxed(W2, &T, &r)?;

        Ok((
            Self {
                commitment_T,
                _random_oracle: PhantomData,
            },
            (U, W),
        ))
    }

    #[cfg(test)]
    pub fn verify_with_relaxed(
        &self,
        random_oracle: &mut RO,
        U1: &RelaxedR1CSInstance<G, C>,
        U2: &RelaxedR1CSInstance<G, C>,
    ) -> Result<RelaxedR1CSInstance<G, C>, r1cs::Error> {
        random_oracle.absorb_non_native(&U1);
        random_oracle.absorb_non_native(&U2);

        random_oracle.absorb(&self.commitment_T.into_affine());

        let r = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U = U1.fold_with_relaxed(U2, &self.commitment_T, &r)?;

        Ok(U)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::poseidon_config;
    use crate::{pedersen::PedersenCommitment, r1cs::*, test_utils::setup_test_r1cs};
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};

    #[test]
    fn prove_verify() {
        prove_verify_with_curve::<
            ark_pallas::PallasConfig,
            PedersenCommitment<ark_pallas::Projective>,
        >()
        .unwrap()
    }

    fn prove_verify_with_curve<G, C>() -> Result<(), r1cs::Error>
    where
        G: SWCurveConfig,
        G::BaseField: PrimeField + Absorb,
        G::ScalarField: Absorb,
        C: CommitmentScheme<Projective<G>, SetupAux = ()>,
        C::PP: Clone,
    {
        let config = poseidon_config::<G::BaseField>();

        let (shape, U2, W2, pp) = setup_test_r1cs::<G, C>(3, None, &());

        let U1 = RelaxedR1CSInstance::<Projective<G>, C>::new(&shape);
        let W1 = RelaxedR1CSWitness::zero(&shape);

        let U2 = RelaxedR1CSInstance::from(&U2);
        let W2 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &W2);

        let mut random_oracle = PoseidonSponge::new(&config);

        let (proof, (folded_U, folded_W)) =
            NIFSProof::<Projective<G>, C, PoseidonSponge<G::BaseField>>::prove_with_relaxed(
                &pp,
                &mut random_oracle,
                &shape,
                (&U1, &W1),
                (&U2, &W2),
            )?;

        let mut random_oracle = PoseidonSponge::new(&config);
        let v_folded_U = proof.verify_with_relaxed(&mut random_oracle, &U1, &U2)?;
        assert_eq!(folded_U, v_folded_U);

        shape.is_relaxed_satisfied(&folded_U, &folded_W, &pp)?;

        let U1 = folded_U;
        let W1 = folded_W;

        let (_, U2, W2, _) = setup_test_r1cs(5, Some(&pp), &());
        let U2 = RelaxedR1CSInstance::from(&U2);
        let W2 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &W2);

        let mut random_oracle = PoseidonSponge::new(&config);
        let (proof, (folded_U, folded_W)) =
            NIFSProof::prove_with_relaxed(&pp, &mut random_oracle, &shape, (&U1, &W1), (&U2, &W2))?;

        let mut random_oracle = PoseidonSponge::new(&config);
        let v_folded_U = proof.verify_with_relaxed(&mut random_oracle, &U1, &U2)?;
        assert_eq!(folded_U, v_folded_U);

        shape.is_relaxed_satisfied(&folded_U, &folded_W, &pp)?;

        Ok(())
    }
}
