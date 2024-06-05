use core::marker::PhantomData;
use ark_ff::{BigInt, PrimeField};

pub use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{
        fp::{AllocatedFp, FpVar},
        FieldVar,
    },
    R1CSVar,
};
pub use ark_relations::{
    lc,
    r1cs::{SynthesisError, SynthesisMode, Variable, ConstraintSystemRef},
};

use nexus_vm::{
    circuit::{build_constraints, ARITY},
    machines::nop_vm,
    memory::{Memory, MemoryProof},
    trace::{trace, Trace},
};
use nexus_nova::StepCircuit;

use crate::prover::nova::error::*;

pub struct Tr<F: PrimeField, P: MemoryProof>(pub Trace<P>, pub PhantomData<F>);

impl<F: PrimeField, P: MemoryProof> Tr<F, P> {
    pub fn steps(&self) -> usize {
        self.0.blocks.len()
    }

    pub fn instructions(&self) -> usize {
        self.0.k * self.0.blocks.len()
    }

    pub fn input(&self, index: usize) -> Result<Vec<F>, ProofError> {
        self.0.input(index).ok_or(ProofError::InvalidIndex(index))
    }
}

pub fn nop_circuit<F: PrimeField, M: Memory>(k: usize) -> Result<Tr<F, M::Proof>, ProofError> {
    let mut vm = nop_vm::<M>(1);
    let trace = trace(&mut vm, k, false)?;
    Ok(Tr(trace, PhantomData))
}

impl<F: PrimeField, P: MemoryProof> StepCircuit<F> for Tr<F, P> {
    const ARITY: usize = ARITY;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        k: &FpVar<F>,
        z: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let index = k.value().map_or(0, |s| match s.into_bigint() {
            BigInt(l) => l[0] as usize,
        });
        build_constraints(cs, index, z, &self.0)
    }
}
