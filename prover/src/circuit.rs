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
    vm::memory::path::{poseidon_config, ParamsVar},
    vm::trace::{trace, Trace, Block, Witness},
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
        v.push(b.steps[0].pc_path.root);
        v
    }
}

pub fn nop_circuit(k: usize) -> Result<Tr, ProofError> {
    let mut vm = nop_vm(0);
    let trace = trace(&mut vm, k, false)?;
    Ok(Tr::new(trace))
}

fn add_paths(cs: CS, w: &Witness, vars: &[FpVar<F1>]) -> Result<(), SynthesisError> {
    let params = poseidon_config();
    let params = ParamsVar::new_constant(cs.clone(), params)?;

    // TODO: fixme (constants) - see init_cs in riscv-circuit
    let root_in = &vars[Tr::ARITY];
    let root_out = &vars[Tr::ARITY * 2];
    let mem = Tr::ARITY * 2 + 1;

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
    z: &[FpVar<F1>],
    w: &Witness,
    rcs: R1CS,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut vars: Vec<FpVar<F1>> = Vec::new();
    let mut output: Vec<FpVar<F1>> = Vec::new();

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

fn build_constraints(
    cs: CS,
    index: usize,
    z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let witness_only = match cs.borrow().unwrap().mode {
        SynthesisMode::Setup => false,
        SynthesisMode::Prove { construct_matrices } => !construct_matrices,
    };

    let b = tr.block(index);
    let mut z = z;
    let mut v = Vec::new();

    for w in b {
        let rcs = big_step(&w, false);
        v = build_constraints_partial(cs.clone(), witness_only, z, &w, rcs)?;
        z = &v;
    }

    Ok(v)
}

impl StepCircuit<F1> for Tr {
    const ARITY: usize = 34;

    fn generate_constraints(
        &self,
        cs: CS,
        k: &FpVar<F1>,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let index = k.value().map_or(0, |s| match s.into_bigint() {
            BigInt(l) => l[0] as usize,
        });
        build_constraints(cs, index, z, self)
    }
}
