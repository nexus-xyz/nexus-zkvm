use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_std::Zero;

use super::{secondary, Error};
use crate::{
    absorb::CryptographicSpongeExt,
    commitment::CommitmentScheme,
    r1cs,
    utils::{cast_field_element, cast_field_element_unique},
};

pub(crate) mod relaxed;

pub(crate) use secondary::SecondaryCircuit;

pub use crate::nifs::{NIFSProof, SQUEEZE_ELEMENTS_BIT_SIZE};

pub(crate) type R1CSShape<G> = r1cs::R1CSShape<Projective<G>>;
pub(crate) type R1CSInstance<G, C> = r1cs::R1CSInstance<Projective<G>, C>;
pub(crate) type R1CSWitness<G> = r1cs::R1CSWitness<Projective<G>>;
pub(crate) type RelaxedR1CSInstance<G, C> = r1cs::RelaxedR1CSInstance<Projective<G>, C>;
pub(crate) type RelaxedR1CSWitness<G> = r1cs::RelaxedR1CSWitness<Projective<G>>;

/// Non-interactive multi-folding scheme proof.
pub struct NIMFSProof<
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    RO,
> {
    pub(crate) commitment_T: C1::Commitment,
    pub(crate) commitment_E_proof: secondary::Proof<G2, C2>,
    pub(crate) commitment_W_proof: secondary::Proof<G2, C2>,
    pub(crate) proof_secondary: NIFSProof<Projective<G2>, C2, RO>,
}

impl<G1, G2, C1, C2, RO> Clone for NIMFSProof<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            commitment_T: self.commitment_T,
            commitment_E_proof: self.commitment_E_proof.clone(),
            commitment_W_proof: self.commitment_W_proof.clone(),
            proof_secondary: self.proof_secondary.clone(),
        }
    }
}

impl<G1, G2, C1, C2, RO> NIMFSProof<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    RO: CryptographicSponge,
{
    pub fn prove<SC: SecondaryCircuit<G1>>(
        pp: &C1::PP,
        pp_secondary: &C2::PP,
        config: &RO::Config,
        vk: &G1::ScalarField,
        (shape, shape_secondary): (&R1CSShape<G1>, &R1CSShape<G2>),
        (U, W): (&RelaxedR1CSInstance<G1, C1>, &RelaxedR1CSWitness<G1>),
        (U_secondary, W_secondary): (&RelaxedR1CSInstance<G2, C2>, &RelaxedR1CSWitness<G2>),
        (u, w): (&R1CSInstance<G1, C1>, &R1CSWitness<G1>),
    ) -> Result<
        (
            Self,
            (RelaxedR1CSInstance<G1, C1>, RelaxedR1CSWitness<G1>),
            (RelaxedR1CSInstance<G2, C2>, RelaxedR1CSWitness<G2>),
        ),
        Error,
    > {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&vk);
        random_oracle.absorb(&U);
        random_oracle.absorb(&u);
        random_oracle.absorb_non_native(&U_secondary);

        let (T, _commitment_T) = r1cs::commit_T(shape, pp, U, W, u, w)?;
        random_oracle.absorb_non_native(&_commitment_T);

        let r_0: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let r_0_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&r_0) };

        let folded_U = U.fold(u, &_commitment_T, &r_0_scalar)?;
        let folded_W = W.fold(w, &T, &r_0_scalar)?;

        // each trace is (U, W)
        let E_comm_trace = SC::synthesize::<G2, C2>(
            secondary::relaxed::Circuit {
                g1: U.commitment_E,
                g2: _commitment_T,
                g3: Projective::zero(),
                g_out: folded_U.commitment_E,
                r: r_0,
            },
            pp_secondary,
        )?;
        let W_comm_trace = SC::synthesize::<G2, C2>(
            secondary::relaxed::Circuit {
                g1: U.commitment_W,
                g2: u.commitment_W,
                g3: Projective::zero(),
                g_out: folded_U.commitment_W,
                r: r_0,
            },
            pp_secondary,
        )?;
        debug_assert!(shape_secondary
            .is_satisfied(&E_comm_trace.0, &E_comm_trace.1, pp_secondary)
            .is_ok());
        debug_assert!(shape_secondary
            .is_satisfied(&W_comm_trace.0, &W_comm_trace.1, pp_secondary)
            .is_ok());

        let (T, commitment_T) = r1cs::commit_T(
            shape_secondary,
            pp_secondary,
            U_secondary,
            W_secondary,
            &E_comm_trace.0,
            &E_comm_trace.1,
        )?;
        random_oracle.absorb_non_native(&E_comm_trace.0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&r_0_scalar);

        let r_1: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary_temp = U_secondary.fold(&E_comm_trace.0, &commitment_T, &r_1)?;
        let W_secondary_temp = W_secondary.fold(&E_comm_trace.1, &T, &r_1)?;

        let commitment_E_proof = secondary::Proof {
            commitment_T,
            U: E_comm_trace.0,
        };

        let (T, commitment_T) = r1cs::commit_T(
            shape_secondary,
            pp_secondary,
            &U_secondary_temp,
            &W_secondary_temp,
            &W_comm_trace.0,
            &W_comm_trace.1,
        )?;
        random_oracle.absorb_non_native(&W_comm_trace.0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_1));

        let r_2: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary_temp.fold(&W_comm_trace.0, &commitment_T, &r_2)?;
        let W_secondary = W_secondary_temp.fold(&W_comm_trace.1, &T, &r_2)?;

        let commitment_W_proof = secondary::Proof {
            commitment_T,
            U: W_comm_trace.0,
        };

        let proof = Self {
            commitment_T: _commitment_T,
            commitment_E_proof,
            commitment_W_proof,
            proof_secondary: NIFSProof::new(),
        };

        Ok((proof, (folded_U, folded_W), (U_secondary, W_secondary)))
    }

    #[cfg(test)]
    pub fn verify(
        &self,
        config: &RO::Config,
        vk: &G1::ScalarField,
        U: &RelaxedR1CSInstance<G1, C1>,
        U_secondary: &RelaxedR1CSInstance<G2, C2>,
        u: &R1CSInstance<G1, C1>,
    ) -> Result<(RelaxedR1CSInstance<G1, C1>, RelaxedR1CSInstance<G2, C2>), Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&vk);
        random_oracle.absorb(&U);
        random_oracle.absorb(&u);
        random_oracle.absorb_non_native(&U_secondary);
        random_oracle.absorb_non_native(&self.commitment_T);

        let r_0: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let r_0_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&r_0) };

        let secondary::Proof {
            U: comm_E_proof,
            commitment_T,
        } = &self.commitment_E_proof;
        let pub_io = comm_E_proof
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != r_0 || pub_io.g1 != U.commitment_E || pub_io.g2 != self.commitment_T {
            return Err(Error::InvalidPublicInput);
        }

        let commitment_E = pub_io.g_out;
        random_oracle.absorb_non_native(&comm_E_proof);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&r_0_scalar);

        let r_1: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let secondary::Proof {
            U: comm_W_proof,
            commitment_T: _commitment_T,
        } = &self.commitment_W_proof;
        let pub_io = comm_W_proof
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != r_0 || pub_io.g1 != U.commitment_W || pub_io.g2 != u.commitment_W {
            return Err(Error::InvalidPublicInput);
        }

        let commitment_W = pub_io.g_out;
        random_oracle.absorb_non_native(&comm_W_proof);
        random_oracle.absorb(&_commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_1));

        let r_2 = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let folded_U = RelaxedR1CSInstance::<G1, C1> {
            commitment_W,
            commitment_E,
            X: U.X
                .iter()
                .zip(&u.X)
                .map(|(a, b)| *a + r_0_scalar * *b)
                .collect(),
        };

        let U_secondary_temp = U_secondary.fold(comm_E_proof, commitment_T, &r_1)?;
        let U_secondary = U_secondary_temp.fold(comm_W_proof, _commitment_T, &r_2)?;

        Ok((folded_U, U_secondary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nifs::tests::synthesize_r1cs, pedersen::PedersenCommitment, poseidon_config};

    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;

    use std::fmt;

    #[test]
    fn prove_verify() {
        prove_verify_with_cycle::<
            ark_pallas::PallasConfig,
            ark_vesta::VestaConfig,
            PedersenCommitment<ark_pallas::Projective>,
            PedersenCommitment<ark_vesta::Projective>,
        >()
        .unwrap();
    }

    fn prove_verify_with_cycle<G1, G2, C1, C2>() -> Result<(), Error>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: CommitmentScheme<Projective<G1>, Commitment = Projective<G1>> + fmt::Debug,
        C2: CommitmentScheme<Projective<G2>, Commitment = Projective<G2>> + fmt::Debug,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let (shape, u, w, pp) = synthesize_r1cs::<G1, C1>(3, None);
        let shape_secondary = secondary::Circuit::<G1>::setup_shape::<G2>()?;

        let pp_secondary = C2::setup(shape_secondary.num_vars + shape_secondary.num_constraints);

        let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
        let W = RelaxedR1CSWitness::<G1>::zero(&shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (proof, (folded_U, folded_W), (folded_U_secondary, folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove::<
                secondary::Circuit<G1>,
            >(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            )?;

        shape_secondary
            .is_relaxed_satisfied(&folded_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        let (_U, _U_secondary) = proof.verify(&config, &vk, &U, &U_secondary, &u)?;

        assert_eq!(_U, folded_U);
        assert_eq!(_U_secondary, folded_U_secondary);
        shape.is_relaxed_satisfied(&_U, &folded_W, &pp).unwrap();

        let (_, u, w, _) = synthesize_r1cs::<G1, C1>(5, Some(&pp));

        let (proof, (_folded_U, folded_W), (_folded_U_secondary, _folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove::<
                secondary::Circuit<G1>,
            >(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&folded_U, &folded_W),
                (&folded_U_secondary, &folded_W_secondary),
                (&u, &w),
            )?;

        shape_secondary
            .is_relaxed_satisfied(&folded_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        let (_U, _U_secondary) = proof.verify(&config, &vk, &folded_U, &folded_U_secondary, &u)?;

        assert_eq!(_U, _folded_U);
        assert_eq!(_U_secondary, _folded_U_secondary);
        shape.is_relaxed_satisfied(&_U, &folded_W, &pp).unwrap();

        Ok(())
    }
}
