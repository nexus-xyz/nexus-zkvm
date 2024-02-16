//! Integration with ArkWorks R1CS circuits.

use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::{AllocatedFp, FpVar},
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError, Variable},
};

use crate::{
    error::Result,
    memory::MemoryProof,
    trace::{Block, Trace, Witness},
};

use super::{
    nvm::{step, ARITY},
    r1cs::{R1CS, V, ZERO},
    F,
};

type CS = ConstraintSystemRef<F>;

fn add_memory_proofs<P: MemoryProof>(
    cs: CS,
    w: &Witness<P>,
    vars: &[FpVar<F>],
) -> Result<(), SynthesisError> {
    let params = P::params(cs.clone())?;

    // TODO: fixme (constants) - see init_cs in riscv module
    let root_in = &vars[ARITY];
    let root_out = &vars[ARITY * 2];
    let mem = ARITY * 2 + 1;

    w.pc_proof
        .circuit(cs.clone(), &params, root_in, &vars[mem..])?;
    w.read_proof
        .circuit(cs.clone(), &params, root_in, &vars[mem + 2..])?;
    w.write_proof
        .circuit(cs.clone(), &params, root_out, &vars[mem + 4..])?;

    Ok(())
}

fn build_constraints_partial(
    cs: CS,
    witness_only: bool,
    z: &[FpVar<F>],
    w: &Witness<impl MemoryProof>,
    rcs: R1CS,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut vars: Vec<FpVar<F>> = Vec::new();
    let mut output: Vec<FpVar<F>> = Vec::new();

    for (i, x) in rcs.w.iter().enumerate() {
        if rcs.input_range().contains(&i) {
            let fp = &z[i - rcs.input_range().start];
            vars.push(fp.clone())
        } else if rcs.output_range().contains(&i) {
            let fp = FpVar::Var(AllocatedFp::new_witness(cs.clone(), || Ok(*x))?);
            vars.push(fp.clone());
            output.push(fp)
        } else {
            let fp = FpVar::Var(AllocatedFp::new_witness(cs.clone(), || Ok(*x))?);
            vars.push(fp);
        }
    }

    add_memory_proofs(cs.clone(), w, &vars)?;

    if witness_only {
        return Ok(output);
    }

    let row = |a: &V| {
        a.iter().enumerate().fold(lc!(), |lc, (i, x)| {
            if x == &ZERO {
                lc
            } else {
                match &vars[i] {
                    FpVar::Constant(f) => lc + (*x * f, Variable::One),
                    FpVar::Var(av) => lc + (*x, av.variable),
                }
            }
        })
    };

    for i in 0..rcs.a.len() {
        cs.enforce_constraint(row(&rcs.a[i]), row(&rcs.b[i]), row(&rcs.c[i]))?;
    }

    Ok(output)
}

pub fn build_constraints<P: MemoryProof>(
    cs: CS,
    index: usize,
    z: &[FpVar<F>],
    tr: &Trace<P>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let witness_only = !cs.should_construct_matrices();

    let b: &Block<P> = match tr.block(index) {
        Some(b) => b,
        None => return Err(SynthesisError::AssignmentMissing),
    };
    let mut z = z;
    let mut v = Vec::new();

    for w in b {
        let rcs = step(&w, witness_only);
        v = build_constraints_partial(cs.clone(), witness_only, z, &w, rcs)?;
        z = &v;
    }

    Ok(v)
}
