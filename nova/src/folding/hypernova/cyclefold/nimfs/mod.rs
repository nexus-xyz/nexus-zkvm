use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::Zero;

use ark_spartan::polycommitments::{PolyCommitmentScheme, VectorCommitmentScheme};

use super::{secondary, Error};
use crate::{
    absorb::CryptographicSpongeExt,
    ccs,
    r1cs,
    utils::{cast_field_element, cast_field_element_unique},
};

/// Non-interactive multi-folding scheme proof.
pub struct NIMFSProof<
    G1: SWCurveConfig,
    G2: SWCurveConfig,
    PC1: PolyCommitmentScheme<Projective<G1>>,
    PC2: PolyCommitmentScheme<Projective<G2>>,
    VC1: PolyCommitmentScheme<Projective<G1>>,
    VC2: PolyCommitmentScheme<Projective<G2>>,
    RO,
> {
    pub(crate) commitment_T: VC1::Commitment,
    pub(crate) commitment_E_proof: [secondary::Proof<G2, VC2>; 2],
    pub(crate) commitment_W_proof: secondary::Proof<G2, VC2>,
    pub(crate) proof_secondary: nova::NIFSProof<Projective<G2>, VC2, RO>,
}

impl<G1, G2, PC1, PC2, VC1, VC2, RO> NIMFSProof<G1, G2, PC1, PC2, VC1, VC2, RO>
where
    G1: SWCurveConfig<BaseField = G2::ScalarField, ScalarField = G2::BaseField>,
    G2: SWCurveConfig,
    PC1: PolyCommitmentScheme<Projective<G1>>,
    PC2: PolyCommitmentScheme<Projective<G2>>
    VC1: VectorCommitmentScheme<Projective<G1>>,
    VC2: VectorCommitmentScheme<Projective<G2>>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    RO: CryptographicSponge,
{
    pub fn prove(
        pck: &PC1::CK,
        pck_secondary: &PC2::CK,
        vck: &VC1::CK,
        vck_secondary: &VC2::CK,
        config: &RO::Config,
        // check
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

        // PART 1: Basic NIMFS for HyperNova

        (proof, (U, W), rho) = hypernova::NIMFSProof::prove_as_subprotocol(random_oracle, shape, (U, W), (u, w));

        // PART 2: Generate Internal Instance and Commit to T

        // PART 3: Fold Internal Instance

        // PART 4: Return


    }
}
