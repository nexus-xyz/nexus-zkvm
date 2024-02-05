use ark_ff::BigInt;
pub use ark_relations::{
    lc,
    r1cs::{Variable, SynthesisMode, SynthesisError},
};
pub use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    fields::{
        fp::{FpVar, AllocatedFp},
        FieldVar,
    },
};

use nexus_vm::{
    eval::halt_vm,
    trace::{Trace, trace},
    circuit::{ARITY, build_constraints},
};

use crate::error::*;
use crate::types::*;

pub struct Tr(pub Trace);

impl Tr {
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

pub fn nop_circuit(k: usize) -> Result<Tr, ProofError> {
    let mut vm = halt_vm();
    let trace = trace(&mut vm, k, false)?;
    Ok(Tr(trace))
}

impl StepCircuit<F1> for Tr {
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
