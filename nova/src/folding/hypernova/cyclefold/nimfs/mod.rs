#![allow(unused)]

use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

use ark_spartan::polycommitments::{PolyCommitmentScheme, PolyCommitmentTrait};

use crate::commitment::{Commitment, CommitmentScheme};

pub(crate) use crate::folding::hypernova::nimfs::NIMFSProof as HNProof;
pub use crate::folding::hypernova::nimfs::SQUEEZE_ELEMENTS_BIT_SIZE;

pub(crate) use super::{secondary, CCSInstance, CCSShape, CCSWitness, Error, LCCSInstance};
pub(crate) use crate::folding::cyclefold::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness};
use crate::{absorb::CryptographicSpongeExt, r1cs, safe_log, utils::cast_field_element_unique};

/// Non-interactive multi-folding scheme proof.
pub struct NIMFSProof<
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO,
> {
    pub(crate) commitment_W_proof: secondary::Proof<G2, C2>,
    pub(crate) hypernova_proof: HNProof<Projective<G1>, RO>,
    pub(crate) _poly_commitment: PhantomData<C1::Commitment>,
}

impl<G1, G2, C1, C2, RO> Clone for NIMFSProof<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
{
    fn clone(&self) -> Self {
        Self {
            commitment_W_proof: self.commitment_W_proof.clone(),
            hypernova_proof: self.hypernova_proof.clone(),
            _poly_commitment: self._poly_commitment,
        }
    }
}

impl<G1, G2, C1, C2, RO> NIMFSProof<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    RO: CryptographicSponge,
{
    pub fn prove(
        pp_secondary: &C2::PP,
        config: &RO::Config,
        vk: &G1::ScalarField,
        (shape, shape_secondary): (&CCSShape<G1>, &R1CSShape<G2>),
        (U, W): (&LCCSInstance<G1, C1>, &CCSWitness<G1>),
        (U_secondary, W_secondary): (&RelaxedR1CSInstance<G2, C2>, &RelaxedR1CSWitness<G2>),
        (u, w): (&CCSInstance<G1, C1>, &CCSWitness<G1>),
    ) -> Result<
        (
            Self,
            (LCCSInstance<G1, C1>, CCSWitness<G1>),
            (RelaxedR1CSInstance<G2, C2>, RelaxedR1CSWitness<G2>),
        ),
        Error,
    > {
        let mut random_oracle = RO::new(config);

        // it is important we absorb this **before** squeezing from the random oracle within the HyperNova subprotocol
        random_oracle.absorb_non_native(&U_secondary);

        let (hypernova_proof, (folded_U, folded_W), rho) =
            HNProof::prove_as_subprotocol(&mut random_oracle, vk, shape, (U, W), (u, w))?;

        // The PolyCommitment trait only guarantees the commitment can be represented by a vector of field elements. However,
        // it makes sense to implement HyperNova Cyclefold assuming the commitment is just a single field element, because we
        // will be using such a scheme for now (Zeromorph) and it leads to a minimally-sized secondary circuit. We expect for
        // these .unwrap() calls to panic with any attempt to use an incompatible poly commitment scheme.
        let W_comm_trace = secondary::synthesize::<G1, G2, C2>(
            secondary::Circuit {
                g1: U
                    .commitment_W
                    .clone()
                    .try_into_affine_point()
                    .unwrap()
                    .into(),
                g2: u
                    .commitment_W
                    .clone()
                    .try_into_affine_point()
                    .unwrap()
                    .into(),
                g_out: folded_U
                    .commitment_W
                    .clone()
                    .try_into_affine_point()
                    .unwrap()
                    .into(),
                r: rho,
            },
            pp_secondary,
        )?;
        debug_assert!(shape_secondary
            .is_satisfied(&W_comm_trace.0, &W_comm_trace.1, pp_secondary)
            .is_ok());

        let (T, commitment_T) = r1cs::commit_T(
            shape_secondary,
            pp_secondary,
            U_secondary,
            W_secondary,
            &W_comm_trace.0,
            &W_comm_trace.1,
        )?;
        random_oracle.absorb_non_native(&W_comm_trace.0);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&rho));

        let rho_p: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary.fold(&W_comm_trace.0, &commitment_T, &rho_p)?;
        let W_secondary = W_secondary.fold(&W_comm_trace.1, &T, &rho_p)?;

        let commitment_W_proof = secondary::Proof { commitment_T, U: W_comm_trace.0 };

        let proof = Self {
            commitment_W_proof,
            hypernova_proof,
            _poly_commitment: PhantomData,
        };

        Ok((proof, (folded_U, folded_W), (U_secondary, W_secondary)))
    }

    #[cfg(any(test, feature = "spartan"))]
    pub fn verify(
        &self,
        config: &RO::Config,
        vk: &G1::ScalarField,
        shape: &CCSShape<G1>,
        U: &LCCSInstance<G1, C1>,
        U_secondary: &RelaxedR1CSInstance<G2, C2>,
        u: &CCSInstance<G1, C1>,
    ) -> Result<(LCCSInstance<G1, C1>, RelaxedR1CSInstance<G2, C2>), Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb_non_native(&U_secondary);

        let (folded_U, rho) =
            self.hypernova_proof
                .verify_as_subprotocol(&mut random_oracle, vk, shape, U, u)?;

        let secondary::Proof { U: comm_W_proof, commitment_T } = &self.commitment_W_proof;
        let pub_io = comm_W_proof
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != rho
            || pub_io.g1
                != Into::<Projective<G1>>::into(
                    U.commitment_W.clone().try_into_affine_point().unwrap(),
                )
            || pub_io.g2
                != Into::<Projective<G1>>::into(
                    u.commitment_W.clone().try_into_affine_point().unwrap(),
                )
        {
            return Err(Error::InvalidPublicInput);
        }

        random_oracle.absorb_non_native(&comm_W_proof);
        random_oracle.absorb(&commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&rho));

        let rho_p =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary.fold(comm_W_proof, commitment_T, &rho_p)?;

        Ok((folded_U, U_secondary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::poseidon_config;
    use crate::{
        ccs::{mle::vec_to_mle, CCSWitness, LCCSInstance},
        pedersen::PedersenCommitment,
        r1cs::tests::to_field_elements,
        test_utils::setup_test_ccs,
        zeromorph::Zeromorph,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test]
    fn prove_verify() {
        prove_verify_with_cycle::<
            ark_bn254::g1::Config,
            ark_grumpkin::GrumpkinConfig,
            Zeromorph<ark_bn254::Bn254>,
            PedersenCommitment<ark_grumpkin::Projective>,
        >()
        .unwrap();
    }

    fn prove_verify_with_cycle<G1, G2, C1, C2>() -> Result<(), Error>
    where
        G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
        G2: SWCurveConfig,
        C1: PolyCommitmentScheme<Projective<G1>>,
        C2: CommitmentScheme<Projective<G2>, SetupAux = ()>,
        G1::BaseField: PrimeField + Absorb,
        G2::BaseField: PrimeField + Absorb,
        C1::PolyCommitmentKey: Clone,
    {
        let config = poseidon_config();

        let vk = G1::ScalarField::ONE;

        let mut rng = test_rng();
        let (shape, u, w, ck) = setup_test_ccs::<G1, C1>(3, None, Some(&mut rng));

        let shape_secondary = secondary::setup_shape::<G1, G2>()?;

        let pp_secondary = C2::setup(
            shape_secondary.num_vars + shape_secondary.num_constraints,
            b"test",
            &(),
        );

        let X = to_field_elements::<Projective<G1>>((vec![0; shape.num_io]).as_slice());
        let W = CCSWitness::zero(&shape);

        let commitment_W = W.commit::<C1>(&ck);

        let s = safe_log!(shape.num_constraints);
        let rs: Vec<G1::ScalarField> = (0..s).map(|_| G1::ScalarField::rand(&mut rng)).collect();

        let z = [X.as_slice(), W.W.as_slice()].concat();
        let vs: Vec<G1::ScalarField> = ark_std::cfg_iter!(&shape.Ms)
            .map(|M| {
                vec_to_mle(M.multiply_vec(&z).as_slice()).evaluate::<Projective<G1>>(rs.as_slice())
            })
            .collect();

        let U = LCCSInstance::<Projective<G1>, C1>::new(
            &shape,
            &commitment_W,
            &X,
            rs.as_slice(),
            vs.as_slice(),
        )?;

        let U_secondary = RelaxedR1CSInstance::<G2, C2>::new(&shape_secondary);
        let W_secondary = RelaxedR1CSWitness::<G2>::zero(&shape_secondary);

        let (proof, (folded_U, folded_W), (folded_U_secondary, folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&U, &W),
                (&U_secondary, &W_secondary),
                (&u, &w),
            )?;

        shape
            .is_satisfied_linearized(&folded_U, &folded_W, &ck)
            .unwrap();

        shape_secondary
            .is_relaxed_satisfied(&folded_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        let (_U, _U_secondary) = proof.verify(&config, &vk, &shape, &U, &U_secondary, &u)?;

        assert_eq!(_U, folded_U);
        assert_eq!(_U_secondary, folded_U_secondary);
        shape.is_satisfied_linearized(&_U, &folded_W, &ck).unwrap();
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &folded_W_secondary, &pp_secondary)
            .unwrap();

        let (_, u, w, _) = setup_test_ccs(5, Some(&ck), Some(&mut rng));

        let (proof, (_folded_U, folded_W), (_folded_U_secondary, _folded_W_secondary)) =
            NIMFSProof::<_, _, _, _, PoseidonSponge<G1::ScalarField>>::prove(
                &pp_secondary,
                &config,
                &vk,
                (&shape, &shape_secondary),
                (&folded_U, &folded_W),
                (&folded_U_secondary, &folded_W_secondary),
                (&u, &w),
            )?;

        shape
            .is_satisfied_linearized(&_folded_U, &folded_W, &ck)
            .unwrap();

        shape_secondary
            .is_relaxed_satisfied(&_folded_U_secondary, &_folded_W_secondary, &pp_secondary)
            .unwrap();

        let (_U, _U_secondary) =
            proof.verify(&config, &vk, &shape, &folded_U, &folded_U_secondary, &u)?;

        assert_eq!(_U, _folded_U);
        assert_eq!(_U_secondary, _folded_U_secondary);
        shape.is_satisfied_linearized(&_U, &folded_W, &ck).unwrap();
        shape_secondary
            .is_relaxed_satisfied(&_U_secondary, &_folded_W_secondary, &pp_secondary)
            .unwrap();

        Ok(())
    }
}
