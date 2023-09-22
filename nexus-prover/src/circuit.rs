use crate::types::*;

use nexus_riscv_circuit::{
    q::{Q, ZERO},
    r1cs::V,
    Trace,
};

fn q_to_f(q: &Q) -> F1 {
    match q {
        Q::Z(x) => F1::from(*x),
        Q::R(a, b) => F1::from(*a) / F1::from(*b),
    }
}

pub struct Tr(usize, Trace);

impl Tr {
    pub fn new(tr: Trace) -> Self {
        Self(0, tr)
    }

    pub fn steps(&self) -> usize {
        self.1.trace.len()
    }

    pub fn z0(&self) -> Vec<F1> {
        self.1.trace[0][0..34].iter().map(q_to_f).collect()
    }

    pub fn advance(&mut self) {
        self.0 += 1
    }
}

fn build_witness(
    cs: CS,
    z: &[FpVar<F1>],
    tr: &Tr,
) -> Result<(Vec<Variable>, Vec<FpVar<F1>>), SynthesisError> {
    let mut vars: Vec<Variable> = Vec::new();
    let mut output: Vec<FpVar<F1>> = vec![z[0].clone()];

    for (i, x) in tr.1.trace[tr.0].iter().enumerate() {
        if i < 34 {
            if let FpVar::Var(AllocatedFp { variable, .. }) = z[i] {
                vars.push(variable)
            } else {
                panic!()
            }
        } else if i < 67 {
            let av = AllocatedFp::new_witness(cs.clone(), || Ok(q_to_f(x)))?;
            vars.push(av.variable);
            output.push(FpVar::Var(av))
        } else {
            vars.push(cs.new_witness_variable(|| Ok(q_to_f(x)))?)
        }
    }
    Ok((vars, output))
}

#[rustfmt::skip]
fn build_constraints(cs: CS, vars: &[Variable], tr: &Tr) -> Result<(), SynthesisError> {
    let row = |a: &V| {
        a.iter().enumerate().fold(lc!(), |lc, (i, x)| {
            if x == &ZERO {
                lc
            } else {
                lc + (q_to_f(x), vars[i])
            }
        })
    };

    for i in 0..tr.1.cs.a.len() {
        cs.enforce_constraint(
            row(&tr.1.cs.a[i]),
            row(&tr.1.cs.b[i]),
            row(&tr.1.cs.c[i])
        )?;
    }
    Ok(())
}

impl StepCircuit<F1> for Tr {
    const ARITY: usize = 34;

    fn generate_constraints(
        &self,
        cs: CS,
        z: &[FpVar<F1>],
    ) -> Result<Vec<FpVar<F1>>, SynthesisError> {
        let matrices = match cs.borrow().unwrap().mode {
            SynthesisMode::Setup => true,
            SynthesisMode::Prove { construct_matrices } => construct_matrices,
        };

        let (vars, output) = build_witness(cs.clone(), z, self)?;

        if matrices {
            build_constraints(cs, &vars, self)?;
        }
        Ok(output)
    }
}
