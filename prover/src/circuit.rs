use crate::types::*;

use nexus_riscv_circuit::{q::ZERO, r1cs::V, Trace};

use ark_ff::BigInt;
use ark_r1cs_std::R1CSVar;

use std::cmp::min;

pub struct Tr(Trace);

impl Tr {
    pub fn new(tr: Trace) -> Self {
        Self(tr)
    }

    pub fn steps(&self) -> usize {
        self.0.trace.len() / self.0.k
    }

    // note: we assume the last witness is from
    // unimp, which does not change the state of the VM.
    // So, we can repeat it as many times as needed
    pub fn witness(&self, n: usize) -> Vec<F1> {
        let i = min(n, self.0.trace.len() - 1);
        self.0.trace[i].iter().map(|q| q.to_field()).collect()
    }

    // note: -1 is fine here because we assume that the
    // k+1 step is just k instances of the last witness
    pub fn input(&self, n: usize) -> Vec<F1> {
        let i = min(self.0.k * n, self.0.trace.len() - 1);
        self.0.trace[i][self.0.input.clone()]
            .iter()
            .map(|q| q.to_field())
            .collect()
    }
}

// fast version
fn build_witness_offset(
    cs: CS,
    index: usize,
    _z: &[FpVar<F1>],
    tr: &Tr,
    offset: usize,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut output: Vec<FpVar<F1>> = Vec::new();

    let index = tr.0.k * index + offset;
    for (i, x) in tr.witness(index).iter().enumerate() {
        if tr.0.input.contains(&i) {
            // variables already allocated in z
        } else if tr.0.output.contains(&i) {
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
    z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut z = z;
    let mut v = Vec::new();
    for i in 0..tr.0.k {
        v = build_witness_offset(cs.clone(), index, z, tr, i)?;
        z = &v;
    }
    Ok(v)
}

// slow version
fn build_constraints_offset(
    cs: CS,
    index: usize,
    z: &[FpVar<F1>],
    tr: &Tr,
    offset: usize,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut vars: Vec<Variable> = Vec::new();
    let mut output: Vec<FpVar<F1>> = Vec::new();

    let index = tr.0.k * index + offset;
    let w = if tr.0.trace.is_empty() {
        tr.0.cs.w.iter().map(|q| q.to_field()).collect()
    } else {
        tr.witness(index)
    };

    for (i, x) in w.iter().enumerate() {
        if tr.0.input.contains(&i) {
            if let FpVar::Var(AllocatedFp { variable, .. }) = z[i - tr.0.input.start] {
                vars.push(variable)
            } else {
                panic!()
            }
        } else if tr.0.output.contains(&i) {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(*x))?;
            vars.push(av.variable);
            output.push(FpVar::Var(av))
        } else {
            vars.push(cs.new_witness_variable(|| Ok(*x))?)
        }
    }

    let row = |a: &V| {
        a.iter().enumerate().fold(lc!(), |lc, (i, x)| {
            if x == &ZERO {
                lc
            } else {
                lc + (x.to_field(), vars[i])
            }
        })
    };

    for i in 0..tr.0.cs.a.len() {
        cs.enforce_constraint(row(&tr.0.cs.a[i]), row(&tr.0.cs.b[i]), row(&tr.0.cs.c[i]))?;
    }

    Ok(output)
}

fn build_constraints(
    cs: CS,
    index: usize,
    z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut z = z;
    let mut v = Vec::new();
    for i in 0..tr.0.k {
        v = build_constraints_offset(cs.clone(), index, z, tr, i)?;
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
