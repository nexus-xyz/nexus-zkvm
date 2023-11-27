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

use nexus_riscv::{
    nop_vm,
    vm::trace::{trace, Trace, Block},
};
use nexus_riscv_circuit::{
    r1cs::{ZERO, V, R1CS},
    riscv::big_step,
};

use crate::error::*;
use crate::types::*;

pub struct Tr(Trace);

impl Tr {
    pub fn new(tr: Trace) -> Self {
        Self(tr)
    }

    pub fn steps(&self) -> usize {
        self.0.blocks.len()
    }

    pub fn instructions(&self) -> usize {
        self.0.k * self.0.blocks.len()
    }

    pub fn block(&self, index: usize) -> &Block {
        &self.0.blocks[index - self.0.start]
    }

    pub fn input(&self, index: usize) -> Vec<F1> {
        let b = self.block(index);
        let mut v = Vec::new();
        v.push(F1::from(b.regs.pc));
        for x in b.regs.x {
            v.push(F1::from(x));
        }
        v
    }
}

pub fn nop_circuit(k: usize) -> Result<Tr, ProofError> {
    let mut vm = nop_vm(0);
    let trace = trace(&mut vm, k, false)?;
    Ok(Tr::new(trace))
}

// fast version
fn build_witness_partial(cs: CS, rcs: R1CS) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut output: Vec<FpVar<F1>> = Vec::new();

    for (i, x) in rcs.w.iter().enumerate() {
        if rcs.input_range().contains(&i) {
            // variables already allocated in z
        } else if rcs.output_range().contains(&i) {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(*x))?;
            output.push(FpVar::Var(av))
        } else {
            cs.new_witness_variable(|| Ok(*x))?;
        }
    }
    Ok(output)
}

fn build_witness(
    cs: CS,
    index: usize,
    _z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let b = tr.block(index);
    let mut v = Vec::new();
    for w in b {
        let rcs = big_step(&w, true);
        v = build_witness_partial(cs.clone(), rcs)?;
    }
    Ok(v)
}

// slow version
fn build_constraints_partial(
    cs: CS,
    z: &[FpVar<F1>],
    rcs: R1CS,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut vars: Vec<Variable> = Vec::new();
    let mut output: Vec<FpVar<F1>> = Vec::new();

    for (i, x) in rcs.w.iter().enumerate() {
        if rcs.input_range().contains(&i) {
            if let FpVar::Var(AllocatedFp { variable, .. }) = z[i - rcs.input_range().start] {
                vars.push(variable)
            } else {
                panic!()
            }
        } else if rcs.output_range().contains(&i) {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(*x))?;
            vars.push(av.variable);
            output.push(FpVar::Var(av))
        } else {
            vars.push(cs.new_witness_variable(|| Ok(*x))?)
        }
    }

    let row = |a: &V| {
        a.iter().enumerate().fold(
            lc!(),
            |lc, (i, x)| {
                if x == &ZERO {
                    lc
                } else {
                    lc + (*x, vars[i])
                }
            },
        )
    };

    for i in 0..rcs.a.len() {
        cs.enforce_constraint(row(&rcs.a[i]), row(&rcs.b[i]), row(&rcs.c[i]))?;
    }

    Ok(output)
}

fn build_constraints(
    cs: CS,
    index: usize,
    z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let b = tr.block(index);
    let mut z = z;
    let mut v = Vec::new();

    for w in b {
        let rcs = big_step(&w, false);
        v = build_constraints_partial(cs.clone(), z, rcs)?;
        z = &v;
    }

    Ok(v)
}

impl StepCircuit<F1> for Tr {
    const ARITY: usize = 33;

    fn generate_constraints(
        &self,
        cs: CS,
        k: &FpVar<F1>,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let matrices = match cs.borrow().unwrap().mode {
            SynthesisMode::Setup => true,
            SynthesisMode::Prove { construct_matrices } => construct_matrices,
        };

        let index = k.value().map_or(0, |s| match s.into_bigint() {
            BigInt(l) => l[0] as usize,
        });

        if !matrices {
            build_witness(cs, index, z, self)
        } else {
            build_constraints(cs, index, z, self)
        }
    }
}
