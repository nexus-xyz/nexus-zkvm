use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

mod multifold;

pub use multifold::{PublicParams, RecursiveSNARK};

pub trait NovaConstraintSynthesizer<F: PrimeField> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}

pub trait StepCircuit<F: PrimeField> {
    const ARITY: usize;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}
