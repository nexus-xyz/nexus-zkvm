use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_ec::short_weierstrass::{SWCurveConfig, Projective};
use ark_spartan::polycommitments::PolyCommitmentScheme;

pub mod sequential;

pub mod public_params;
pub use crate::folding::hypernova::cyclefold::Error;
use crate::folding::hypernova::cyclefold::LCCSInstance;

pub use crate::circuits::nova::StepCircuit;

pub trait HyperNovaConstraintSynthesizer<G, C>
where
    G: SWCurveConfig,
    C: PolyCommitmentScheme<Projective<G>>,
{
    fn base_instance(
        sumcheck_rounds: usize
    ) -> LCCSInstance<G, C>;

    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<G::ScalarField>,
    ) -> Result<Vec<FpVar<G::ScalarField>>, SynthesisError>;
}
