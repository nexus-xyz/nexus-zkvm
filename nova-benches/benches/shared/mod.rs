use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use nexus_nova::StepCircuit;
use std::marker::PhantomData;

pub const NUM_WARMUP_STEPS: usize = 10;

pub struct NonTrivialTestCircuit<F> {
    num_constraints: usize,
    _p: PhantomData<F>,
}

impl<F> NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    pub fn new(num_constraints: usize) -> Self {
        Self { num_constraints, _p: PhantomData }
    }
}

impl<F> StepCircuit<F> for NonTrivialTestCircuit<F>
where
    F: PrimeField,
{
    const ARITY: usize = 1;

    fn generate_constraints(
        &self,
        _: ConstraintSystemRef<F>,
        _: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Consider an equation: `x^2 = y`, where `x` and `y` are respectively the input and output.
        let mut x = z[0].clone();
        let mut y = x.clone();
        for _ in 0..self.num_constraints {
            y = x.square()?;
            x = y.clone();
        }
        Ok(vec![y])
    }
}
