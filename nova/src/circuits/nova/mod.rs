use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub mod pcd;
pub mod sequential;

pub mod public_params;
pub use crate::folding::nova::cyclefold::Error;

pub trait NovaConstraintSynthesizer<F: PrimeField> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

pub trait StepCircuit<F: PrimeField>: Send + Sync {
    const ARITY: usize;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}
