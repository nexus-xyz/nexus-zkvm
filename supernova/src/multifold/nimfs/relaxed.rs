use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{Field, PrimeField};

use crate::{
    absorb::CryptographicSpongeExt,
    commitment::{Commitment, CommitmentScheme},
    multifold::secondary,
    r1cs,
    utils::{cast_field_element, cast_field_element_unique},
};

use super::{
    Error, NIFSProof, NIMFSProof, R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness,
    SQUEEZE_ELEMENTS_BIT_SIZE,
};

impl<G1, G2, C1, C2, RO> NIMFSProof<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    G2: SWCurveConfig,
    C1: CommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    RO: CryptographicSponge,
{
    pub fn prove_with_relaxed(
        pp: &C1::PP,
        pp_secondary: &C2::PP,
        config: &RO::Config,
        vk: &G1::ScalarField,
        (shape, shape_secondary): (&R1CSShape<G1>, &R1CSShape<G2>),
        (U1, W1): (&RelaxedR1CSInstance<G1, C1>, &RelaxedR1CSWitness<G1>),
        (U1_secondary, W1_secondary): (&RelaxedR1CSInstance<G2, C2>, &RelaxedR1CSWitness<G2>),
        (U2, W2): (&RelaxedR1CSInstance<G1, C1>, &RelaxedR1CSWitness<G1>),
        (U2_secondary, W2_secondary): (&RelaxedR1CSInstance<G2, C2>, &RelaxedR1CSWitness<G2>),
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
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);
        random_oracle.absorb_non_native(&U1_secondary);

        let (T, _commitment_T) = r1cs::commit_T_with_relaxed(shape, pp, U1, W1, U2, W2)?;
        random_oracle.absorb_non_native(&_commitment_T.into());

        let r_0: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let r_0_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&r_0) };

        let folded_U = U1.fold_with_relaxed(U2, &_commitment_T, &r_0_scalar)?;
        let folded_W = W1.fold_with_relaxed(W2, &T, &r_0_scalar)?;

        let g_out = U1.commitment_E + _commitment_T * r_0_scalar;
        // each trace is (U, W)
        let E_comm_trace = [
            secondary::synthesize::<G1, G2, C2>(
                secondary::Circuit {
                    g1: U1.commitment_E.into(),
                    g2: _commitment_T.into(),
                    g_out: g_out.into(),
                    r: r_0,
                },
                pp_secondary,
            )?,
            secondary::synthesize::<G1, G2, C2>(
                secondary::Circuit {
                    g1: g_out.into(),
                    g2: U2.commitment_E.into(),
                    g_out: folded_U.commitment_E.into(),
                    r: unsafe {
                        cast_field_element::<G1::ScalarField, G1::BaseField>(&r_0_scalar.square())
                    },
                },
                pp_secondary,
            )?,
        ];
        let W_comm_trace = secondary::synthesize::<G1, G2, C2>(
            secondary::Circuit {
                g1: U1.commitment_W.into(),
                g2: U2.commitment_W.into(),
                g_out: folded_U.commitment_W.into(),
                r: r_0,
            },
            pp_secondary,
        )?;
        debug_assert!(shape_secondary
            .is_satisfied(&E_comm_trace[0].0, &E_comm_trace[0].1, pp_secondary)
            .is_ok());
        debug_assert!(shape_secondary
            .is_satisfied(&E_comm_trace[1].0, &E_comm_trace[1].1, pp_secondary)
            .is_ok());
        debug_assert!(shape_secondary
            .is_satisfied(&W_comm_trace.0, &W_comm_trace.1, pp_secondary)
            .is_ok());

        // commitment E proof requires folding 2 instances.
        let (T, commitment_T) = r1cs::commit_T(
            shape_secondary,
            pp_secondary,
            U1_secondary,
            W1_secondary,
            &E_comm_trace[0].0,
            &E_comm_trace[0].1,
        )?;
        random_oracle.absorb_non_native(&E_comm_trace[0].0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&r_0_scalar);

        let r_1: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary_temp = U1_secondary.fold(&E_comm_trace[0].0, &commitment_T, &r_1)?;
        let W_secondary_temp = W1_secondary.fold(&E_comm_trace[0].1, &T, &r_1)?;

        let commitment_E_proof_0 = secondary::Proof {
            commitment_T,
            U: E_comm_trace[0].0.clone(),
        };

        let (T, commitment_T) = r1cs::commit_T(
            shape_secondary,
            pp_secondary,
            &U_secondary_temp,
            &W_secondary_temp,
            &E_comm_trace[1].0,
            &E_comm_trace[1].1,
        )?;
        random_oracle.absorb_non_native(&E_comm_trace[1].0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_1));

        let r_2: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary_temp = U_secondary_temp.fold(&E_comm_trace[1].0, &commitment_T, &r_2)?;
        let W_secondary_temp = W_secondary_temp.fold(&E_comm_trace[1].1, &T, &r_2)?;

        let commitment_E_proof_1 = secondary::Proof {
            commitment_T,
            U: E_comm_trace[1].0.clone(),
        };

        // last iteration for commitment to witness
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
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_2));

        let r_3: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary_temp.fold(&W_comm_trace.0, &commitment_T, &r_3)?;
        let W_secondary = W_secondary_temp.fold(&W_comm_trace.1, &T, &r_3)?;

        let commitment_W_proof = secondary::Proof {
            commitment_T,
            U: W_comm_trace.0,
        };

        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_3));
        let (proof_secondary, (U_secondary, W_secondary)) = NIFSProof::prove_with_relaxed(
            pp_secondary,
            &mut random_oracle,
            shape_secondary,
            (&U_secondary, &W_secondary),
            (U2_secondary, W2_secondary),
        )?;

        let proof = Self {
            commitment_T: _commitment_T,
            commitment_E_proof: [commitment_E_proof_0, commitment_E_proof_1],
            commitment_W_proof,
            proof_secondary,
        };

        Ok((proof, (folded_U, folded_W), (U_secondary, W_secondary)))
    }

    #[cfg(test)]
    pub fn verify_with_relaxed(
        &self,
        config: &RO::Config,
        vk: &G1::ScalarField,
        U1: &RelaxedR1CSInstance<G1, C1>,
        U_secondary: &RelaxedR1CSInstance<G2, C2>,
        U2: &RelaxedR1CSInstance<G1, C1>,
        U2_secondary: &RelaxedR1CSInstance<G2, C2>,
    ) -> Result<(RelaxedR1CSInstance<G1, C1>, RelaxedR1CSInstance<G2, C2>), Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&vk);
        random_oracle.absorb(&U1);
        random_oracle.absorb(&U2);
        random_oracle.absorb_non_native(&U_secondary);
        random_oracle.absorb_non_native(&self.commitment_T.into());

        let r_0: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let r_0_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&r_0) };

        let secondary::Proof {
            U: comm_E_proof_0,
            commitment_T,
        } = &self.commitment_E_proof[0];
        let pub_io = comm_E_proof_0
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != r_0
            || pub_io.g1 != U1.commitment_E.into()
            || pub_io.g2 != self.commitment_T.into()
        {
            return Err(Error::InvalidPublicInput);
        }
        let g_out = pub_io.g_out;

        random_oracle.absorb_non_native(&comm_E_proof_0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&r_0_scalar);

        let r_1: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let secondary::Proof {
            U: comm_E_proof_1,
            commitment_T: _commitment_T,
        } = &self.commitment_E_proof[1];
        let pub_io = comm_E_proof_1
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        let r_0_square =
            unsafe { cast_field_element::<G1::ScalarField, G1::BaseField>(&r_0_scalar.square()) };
        if pub_io.r != r_0_square || pub_io.g1 != g_out || pub_io.g2 != U2.commitment_E.into() {
            return Err(Error::InvalidPublicInput);
        }

        // output of the second instance is resulting commitment
        let commitment_E = pub_io.g_out;
        random_oracle.absorb_non_native(&comm_E_proof_1);
        random_oracle.absorb(&_commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_1));

        let r_2: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let secondary::Proof {
            U: comm_W_proof,
            commitment_T: __commitment_T,
        } = &self.commitment_W_proof;
        let pub_io = comm_W_proof
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != r_0
            || pub_io.g1 != U1.commitment_W.into()
            || pub_io.g2 != U2.commitment_W.into()
        {
            return Err(Error::InvalidPublicInput);
        }

        let commitment_W = pub_io.g_out;
        random_oracle.absorb_non_native(&comm_W_proof);
        random_oracle.absorb(&__commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_2));

        let r_3: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let folded_U = RelaxedR1CSInstance::<G1, C1> {
            commitment_W: commitment_W.into(),
            commitment_E: commitment_E.into(),
            X: U1
                .X
                .iter()
                .zip(&U2.X)
                .map(|(x1, x2)| *x1 + r_0_scalar * *x2)
                .collect(),
        };

        let U_secondary_temp = U_secondary.fold(comm_E_proof_0, commitment_T, &r_1)?;
        let U_secondary_temp = U_secondary_temp.fold(comm_E_proof_1, _commitment_T, &r_2)?;
        let U_secondary = U_secondary_temp.fold(comm_W_proof, __commitment_T, &r_3)?;

        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&r_3));
        let U_secondary = self.proof_secondary.verify_with_relaxed(
            &mut random_oracle,
            &U_secondary,
            U2_secondary,
        )?;

        Ok((folded_U, U_secondary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pedersen::PedersenCommitment, poseidon_config, test_utils::setup_test_r1cs};

    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ff::Field;
    use ark_std::{rand::Rng, UniformRand, Zero};

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
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;
        let (shape, _, _, pp) = setup_test_r1cs::<G1, C1>(2, None, &());
        let shape_secondary = secondary::setup_shape::<G1, G2>()?;
        let pp_secondary = C2::setup(
            shape_secondary.num_vars + shape_secondary.num_constraints,
            &(),
        );

        let mut rng = ark_std::test_rng();

        let ((U1, W1), (U1_secondary, W1_secondary)) =
            setup_non_trivial::<G1, G2, C1, C2>(&mut rng, &pp, &pp_secondary)?;
        let ((U2, W2), (U2_secondary, W2_secondary)) =
            setup_non_trivial::<G1, G2, C1, C2>(&mut rng, &pp, &pp_secondary)?;

        let (proof, (U, W), (U_secondary, W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove_with_relaxed(
                &pp,
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U1, &W1),
                (&U1_secondary, &W1_secondary),
                (&U2, &W2),
                (&U2_secondary, &W2_secondary),
            )?;

        shape_secondary
            .is_relaxed_satisfied(&U_secondary, &W_secondary, &pp_secondary)
            .unwrap();

        let (_U, _U_secondary) =
            proof.verify_with_relaxed(&config, &vk, &U1, &U1_secondary, &U2, &U2_secondary)?;

        assert_eq!(_U, U);
        assert_eq!(_U_secondary, U_secondary);
        shape.is_relaxed_satisfied(&U, &W, &pp).unwrap();
        shape_secondary.is_relaxed_satisfied(&U_secondary, &W_secondary, &pp_secondary)?;

        Ok(())
    }

    /// Returns relaxed instance-witness pair, ensuring that commitment to E is not zero.
    fn setup_non_trivial<G1, G2, C1, C2>(
        rng: &mut impl Rng,
        pp: &C1::PP,
        pp_secondary: &C2::PP,
    ) -> Result<
        (
            (RelaxedR1CSInstance<G1, C1>, RelaxedR1CSWitness<G1>),
            (RelaxedR1CSInstance<G2, C2>, RelaxedR1CSWitness<G2>),
        ),
        Error,
    >
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: CommitmentScheme<Projective<G1>, SetupAux = ()>,
        C2: CommitmentScheme<Projective<G2>>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PP: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let (shape, u, w, _) = setup_test_r1cs::<G1, C1>(UniformRand::rand(rng), Some(pp), &());
        let shape_secondary = secondary::setup_shape::<G1, G2>()?;

        let U = RelaxedR1CSInstance::<G1, C1>::new(&shape);
        let W = RelaxedR1CSWitness::<G1>::zero(&shape);

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);
        let (_, (U2, W2), (U2_secondary, W2_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
                pp,
                pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            )?;

        let (_, u, w, _) = setup_test_r1cs::<G1, C1>(UniformRand::rand(rng), Some(pp), &());
        let U1 = RelaxedR1CSInstance::from(&u);
        let W1 = RelaxedR1CSWitness::from_r1cs_witness(&shape, &w);

        let U1_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W1_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (_, (U, W), (U_secondary, W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove_with_relaxed(
                pp,
                pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U1, &W1),
                (&U1_secondary, &W1_secondary),
                (&U2, &W2),
                (&U2_secondary, &W2_secondary),
            )?;

        assert!(!U.commitment_E.into().is_zero());
        Ok(((U, W), (U_secondary, W_secondary)))
    }
}
