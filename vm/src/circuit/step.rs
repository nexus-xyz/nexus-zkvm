//! Integration with ArkWorks R1CS circuits.

use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, Variable, SynthesisError},
};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::{FpVar, AllocatedFp},
};

use crate::{
    error::Result,
    memory::path::{poseidon_config, ParamsVar},
    trace::{Trace, Block, Witness},
};

use super::{
    F,
    r1cs::{ZERO, V, R1CS},
    nvm::{ARITY, step},
};

type CS = ConstraintSystemRef<F>;

fn add_paths(cs: CS, w: &Witness, vars: &[FpVar<F>]) -> Result<(), SynthesisError> {
    let params = poseidon_config();
    let params = ParamsVar::new_constant(cs.clone(), params)?;

    // TODO: fixme (constants) - see init_cs in riscv module
    let root_in = &vars[ARITY];
    let root_out = &vars[ARITY * 2];
    let mem = ARITY * 2 + 1;

    w.pc_path
        .verify_circuit(cs.clone(), &params, root_in, &vars[mem..])?;
    w.read_path
        .verify_circuit(cs.clone(), &params, root_in, &vars[mem + 2..])?;
    w.write_path
        .verify_circuit(cs.clone(), &params, root_out, &vars[mem + 4..])?;

    Ok(())
}

fn build_constraints_partial(
    cs: CS,
    witness_only: bool,
    z: &[FpVar<F>],
    w: &Witness,
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

    add_paths(cs.clone(), w, &vars)?;

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

pub fn build_constraints(
    cs: CS,
    index: usize,
    z: &[FpVar<F>],
    tr: &Trace,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let witness_only = !cs.should_construct_matrices();

    let b: &Block = match tr.block(index) {
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
