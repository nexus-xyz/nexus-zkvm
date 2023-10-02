use crate::types::*;

use nexus_riscv_circuit::{q::ZERO, r1cs::V, Trace};

pub struct Tr(usize, Trace);

impl Tr {
    pub fn new(tr: Trace) -> Self {
        Self(0, tr)
    }

    pub fn steps(&self) -> usize {
        self.1.trace.len() / self.1.k
    }

    pub fn z0(&self) -> Vec<F1> {
        self.1.trace[0][self.1.input.clone()]
            .iter()
            .map(|q| q.to_field())
            .collect()
    }

    pub fn advance(&mut self) {
        self.0 += 1
    }
}

// fast version
fn build_witness_offset(
    cs: CS,
    _z: &[FpVar<F1>],
    tr: &Tr,
    offset: usize,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut output: Vec<FpVar<F1>> = Vec::new();

    let index = tr.1.k * tr.0 + offset;
    for (i, x) in tr.1.trace[index].iter().enumerate() {
        if tr.1.input.contains(&i) {
            // variables already allocated in z
        } else if tr.1.output.contains(&i) {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(x.to_field::<F1>()))?;
            output.push(FpVar::Var(av))
        } else {
            cs.new_witness_variable(|| Ok(x.to_field()))?;
        }
    }
    Ok(output)
}

fn build_witness(cs: CS, z: &[FpVar<F1>], tr: &Tr) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut z = z;
    let mut v = Vec::new();
    for i in 0..tr.1.k {
        v = build_witness_offset(cs.clone(), z, tr, i)?;
        z = &v;
    }
    Ok(v)
}

// slow version
fn build_constraints_offset(
    cs: CS,
    z: &[FpVar<F1>],
    tr: &Tr,
    offset: usize,
) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut vars: Vec<Variable> = Vec::new();
    let mut output: Vec<FpVar<F1>> = Vec::new();

    let index = tr.1.k * tr.0 + offset;
    let w = if index >= tr.1.trace.len() {
        &tr.1.cs.w
    } else {
        &tr.1.trace[index]
    };

    for (i, x) in w.iter().enumerate() {
        if tr.1.input.contains(&i) {
            if let FpVar::Var(AllocatedFp { variable, .. }) = z[i - tr.1.input.start] {
                vars.push(variable)
            } else {
                panic!()
            }
        } else if tr.1.output.contains(&i) {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(x.to_field::<F1>()))?;
            vars.push(av.variable);
            output.push(FpVar::Var(av))
        } else {
            vars.push(cs.new_witness_variable(|| Ok(x.to_field()))?)
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

    for i in 0..tr.1.cs.a.len() {
        cs.enforce_constraint(row(&tr.1.cs.a[i]), row(&tr.1.cs.b[i]), row(&tr.1.cs.c[i]))?;
    }

    Ok(output)
}

fn build_constraints(cs: CS, z: &[FpVar<F1>], tr: &Tr) -> Result<Vec<FpVar<F1>>, SynthesisError> {
    let mut z = z;
    let mut v = Vec::new();
    for i in 0..tr.1.k {
        v = build_constraints_offset(cs.clone(), z, tr, i)?;
        z = &v;
    }
    Ok(v)
}

impl StepCircuit<F1> for Tr {
    const ARITY: usize = 33;

    fn generate_constraints(
        &self,
        cs: CS,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let matrices = match cs.borrow().unwrap().mode {
            SynthesisMode::Setup => true,
            SynthesisMode::Prove { construct_matrices } => construct_matrices,
        };
        if !matrices {
            build_witness(cs, z, self)
        } else {
            build_constraints(cs, z, self)
        }
    }
}
