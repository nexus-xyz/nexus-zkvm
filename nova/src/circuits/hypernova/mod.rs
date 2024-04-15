use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::sponge::{
    constraints::{CryptographicSpongeVar, SpongeWithGadget},
    Absorb,
};
use ark_ec::short_weierstrass::{SWCurveConfig, Projective};
use ark_spartan::polycommitments::PolyCommitmentScheme;

pub mod sequential;

pub mod public_params;
use crate::commitment::CommitmentScheme;
pub use crate::folding::hypernova::cyclefold::{self, Error};
use crate::folding::hypernova::cyclefold::{LCCSInstance, nimfs::NIMFSProof};

pub use crate::circuits::nova::StepCircuit;

pub trait HyperNovaConstraintSynthesizer<G1, G2, C1, C2, RO>
where
    G1: SWCurveConfig,
    G2: SWCurveConfig<BaseField = G1::ScalarField, ScalarField = G1::BaseField>,
    G1::BaseField: PrimeField + Absorb,
    G2::BaseField: PrimeField + Absorb,
    C1: PolyCommitmentScheme<Projective<G1>>,
    C2: CommitmentScheme<Projective<G2>>,
    RO: SpongeWithGadget<G1::ScalarField>,
    RO::Var: CryptographicSpongeVar<G1::ScalarField, RO, Parameters = RO::Config>,
{
    fn base(
        sumcheck_rounds: usize
    ) -> (LCCSInstance<G1, C1>, NIMFSProof<G1, G2, C1, C2, RO>);

    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G1::ScalarField>,
    ) -> Result<Vec<FpVar<G1::ScalarField>>, SynthesisError>;
}
