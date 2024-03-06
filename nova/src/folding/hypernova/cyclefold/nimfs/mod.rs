use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::Zero;

use ark_spartan::polycommitments::{PolyCommitmentScheme, VectorCommitmentScheme};

pub use crate::folding::hypernova::nimfs::{SQUEEZE_ELEMENTS_BIT_SIZE};

use super::{secondary, Error};
use crate::{
    absorb::CryptographicSpongeExt,
    ccs,
    r1cs,
    utils::{cast_field_element, cast_field_element_unique},
};

pub(crate) use crate::folding::cyclefold::{
    CCSShape, CCSInstance, CCSWitness, LCCSInstance, RelaxedR1CSInstance, RelaxedR1CSWitness,
};

/// Non-interactive multi-folding scheme proof.
pub struct NIMFSProof<
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO,
> {
    pub(crate) commitment_T: C2::Commitment,
    pub(crate) commitment_W_proof: secondary::Proof<G2, VC2>,
    pub(crate) hypernova_proof: hypernova::NIMFSProof<Projective<G1>, RO>,
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
        ck: &C1::CK,
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

        random_oracle.absorb(&vk);
        random_oracle.absorb(&U);
        random_oracle.absorb(&u);
        random_oracle.absorb_non_native(&U_secondary);

        let rho: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let rho_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&rho) };

        (hypernova_proof, (folded_U, folded_W), rho_scalar) = hypernova::NIMFSProof::prove_as_subprotocol(random_oracle, shape, (U, W), (u, w));

        let g_out = U.commitment_W + u.commitment_W * rho;
        let W_comm_trace = secondary::synthesize::<G1, G2, C2>(
            secondary::Circuit {
                g1: U.commitment_W.into(),
                g2: u.commitment_W.into(),
                g_out: g_out.into(),
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
        random_oracle.absorb(&rho_scalar);

        let rho_p: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary.fold(&W_comm_trace.0, &commitment_T, &rho_p)?;
        let W_secondary = W_secondary.fold(&W_comm_trace.1, &T, &rho_p)?;

        let commitment_W_proof = secondary::Proof { commitment_T, U: W_comm_trace.0 };

        let proof = Self {
            commitment_T,
            commitment_W_proof,
            hypernova_proof,
        };

        Ok((proof, (folded_U folded_W), (U_secondary, W_secondary)))
    }

    #[cfg(any(test, feature = "spartan"))]
    pub fn verify(
        &self,
        config: &RO::Config,
        vk: &G1::ScalarField,
        U: &LCCSInstance<G1, C1>,
        U_secondary: &RelaxedR1CSInstance<G2, C2>,
        u: &CCSInstance<G1, C1>,
    ) -> Result<(LCCSInstance<G1, C1>, RelaxedR1CSInstance<G2, C2>), Error> {
        let mut random_oracle = RO::new(config);

        random_oracle.absorb(&vk);
        random_oracle.absorb(&U);
        random_oracle.absorb(&u);
        random_oracle.absorb_non_native(&U_secondary);
        random_oracle.absorb_non_native(&self.commitment_T.into());

        let rho: G1::BaseField =
            random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];
        let rho_scalar: G1::ScalarField =
            unsafe { cast_field_element::<G1::BaseField, G1::ScalarField>(&r_0) };

        let folded_U = self.hypernova_proof.verify_as_subprotocol(&mut random_oracle, shape, U, u, &rho_scalar)?;

        let secondary::Proof {
            U: comm_W_proof,
            commitment_T: commitment_T,
        } = &self.commitment_W_proof;
        let pub_io = comm_W_proof
            .parse_secondary_io::<G1>()
            .ok_or(Error::InvalidPublicInput)?;

        if pub_io.r != rho
            || pub_io.g1 != U.commitment_W.into()
            || pub_io.g2 != u.commitment_W.into()
        {
            return Err(Error::InvalidPublicInput);
        }

        let commitment_W = pub_io.g_out;
        random_oracle.absorb_non_native(&comm_W_proof);
        random_oracle.absorb(&_commitment_T.into_affine());
        random_oracle.absorb(&cast_field_element_unique::<G1::BaseField, G1::ScalarField>(&rho));

        let rho_p = random_oracle.squeeze_field_elements_with_sizes(&[SQUEEZE_ELEMENTS_BIT_SIZE])[0];

        let U_secondary = U_secondary.fold(comm_W_proof, commitment_T, &rho_p)?;

        Ok((folded_U, U_secondary))
    }
}
