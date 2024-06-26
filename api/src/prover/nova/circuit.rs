use ark_ff::BigInt;
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
    r1cs::{SynthesisError, SynthesisMode, Variable},
};

use nexus_vm::{
    circuit::{build_constraints, ARITY},
    machines::nop_vm,
    memory::Memory,
    trace::{trace, Trace},
};

use super::error::*;
use super::types::*;

pub struct Tr<M: Memory>(pub Trace<M::Proof>);

impl<M: Memory> Tr<M> {
    pub fn steps(&self) -> usize {
        self.0.blocks.len()
    }

    pub fn instructions(&self) -> usize {
        self.0.k * self.0.blocks.len()
    }

    pub fn input(&self, index: usize) -> Result<Vec<F1>, ProofError> {
        self.0.input(index).ok_or(ProofError::InvalidIndex(index))
    }
}

pub fn nop_circuit<M: Memory>(k: usize) -> Result<Tr<M>, ProofError> {
    let mut vm = nop_vm::<M>(1);
    let trace = trace(&mut vm, k, false)?;
    Ok(Tr(trace))
}

impl<M: Memory> StepCircuit<F1> for Tr<M>
where
    M::Proof: Send + Sync,
{
    const ARITY: usize = ARITY;

    fn generate_constraints(
        &self,
        cs: CS,
        k: &FpVar<F1>,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let index = k.value().map_or(0, |s| match s.into_bigint() {
            BigInt(l) => l[0] as usize,
        });
        build_constraints(cs, index, z, &self.0)
    }
}
