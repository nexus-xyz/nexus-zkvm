use clap::Parser;

use nexus_riscv::load_elf;
use nexus_riscv_circuit::{*, q::*, r1cs::*};

use ff::Field;

use bellpepper_core::{ConstraintSystem, SynthesisError};
use bellpepper::{gadgets::num::AllocatedNum};
use nova_snark::{
    traits::{
        circuit::{StepCircuit, TrivialTestCircuit},
        Group,
    },
    PublicParams,
    RecursiveSNARK,
};
use std::time::Instant;
use std::io::{self,Write};

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;
type F1 = <G1 as Group>::Scalar;
type F2 = <G2 as Group>::Scalar;

#[derive(Clone)]
struct R1CSCircuit {
    a: M,
    b: M,
    c: M,
    trace: Vec<V>
}

fn i128_to_f(x: i128) -> F1 {
    let negative = x < 0;
    let x = x.abs() as u128;

    let low = x as u64;
    let high = (x >> 64) as u64;

    let shift64 = F1::from(0x8000_0000_0000_0000) * F1::from(2);
    let f = F1::from(high) * shift64 + F1::from(low);
    if negative {
        f.neg()
    } else {
        f
    }
}

fn q_to_f(x: &Q) -> F1 {
    match x {
        Q::Z(x) => i128_to_f(*x),
        Q::R(a,b) => i128_to_f(*a) * i128_to_f(*b).invert().unwrap()
    }
}

fn f_to_usize(x: F1) -> usize {
    let bytes: [u8; 32] = x.into();
    let bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
    u32::from_le_bytes(bytes) as usize
}

impl StepCircuit<F1> for R1CSCircuit {
    fn arity(&self) -> usize {
        // witness looks like:
        // 1, pc, x0, ..., x31, pc', x'0, ..., x'31, ...,j, ,,, , j', ...
        // location of j and j' is tracked by bell(man/person/pepper) circuit
        // pc and regs are always in first positions shown above
        // We will use j,pc,x0,...x31 as the input
        34
    }

    fn synthesize<CS: ConstraintSystem<F1>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F1>],
    ) -> Result<Vec<AllocatedNum<F1>>, SynthesisError> {

        // get j value
        let x_0 = z[0].clone();
        let (first,j) = match x_0.get_value() {
            None => (true, 0),
            Some(x) => (false, f_to_usize(x))
        };

        // witness j counter update
        let x_plus_1 = AllocatedNum::alloc(cs.namespace(|| format!("x_plus_1")), || {
            Ok(x_0.get_value().unwrap() + F1::from(1))
        })?;

        // Setup ramaining witness vars
        // Note: ordering is guaranteed in r1cs::init_cs
        let tr = &self.trace[j];
        let vars:Vec<AllocatedNum<F1>> = tr.iter().enumerate().map(|(i,x)| {
            if i >= 1 && i <= 33 {
                z[i].clone()
            } else {
                AllocatedNum::alloc(cs.namespace(||format!("c{i}")), || Ok(q_to_f(x))).expect("")
            }
        }).collect();

        if first {
            // enforce counter update
            cs.enforce(
                || format!("x_i_plus_1 = x_i + 1"),
                |lc| lc + x_0.get_variable() + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + x_plus_1.get_variable(),
            );
            // Construct Circuit that when rendedered to R1CS will
            // be the same as our original R1CS instance

            for row in 0..self.a.len() {
                let a = &self.a[row];
                let b = &self.b[row];
                let c = &self.c[row];
                cs.enforce(
                    || format!("row {row}"),
                    |lc| (0..a.len()).fold(lc, |lc,col| lc + (q_to_f(&a[col]), vars[col].get_variable())),
                    |lc| (0..b.len()).fold(lc, |lc,col| lc + (q_to_f(&b[col]), vars[col].get_variable())),
                    |lc| (0..c.len()).fold(lc, |lc,col| lc + (q_to_f(&c[col]), vars[col].get_variable()))
                );
            }
        }
        // Set outputs
        // Note: ordering is determined by r1cs::init_cs
        let mut res = vec![x_plus_1.clone()];
        for i in 34..67 {
            res.push(vars[i].clone());
        }
        Ok(res)
    }
}

pub fn prove(trace: &Trace) {
    // the clone is not really necessary here
    let circuit_primary = R1CSCircuit {
        a: trace.cs.a.clone(),
        b: trace.cs.b.clone(),
        c: trace.cs.c.clone(),
        trace: trace.trace.clone(),
    };

    let circuit_secondary = TrivialTestCircuit::default();

    println!(
        "Synthesizing Circuit from R1CS with {} vars, {} constraints... ",
        circuit_primary.a.len(),
        circuit_primary.a[0].len(),
    );
    let start = Instant::now();
    let pp = PublicParams::<G1, G2, R1CSCircuit, TrivialTestCircuit<F2>>::setup(
                &circuit_primary,
                &circuit_secondary,
            );
    println!("Public setup complete. {:?}", start.elapsed());

    println!(
        "Primary circuit: {} vars, {} constraints.",
        pp.num_variables().0,
        pp.num_constraints().0
    );
    println!(
        "Secondary circuit: {} vars, {} constraints.",
        pp.num_variables().0,
        pp.num_constraints().1
    );

    // compute initial inputs
    // Note: ordering is guaranteed in r1cs::init_cs
    let mut z0_primary = vec![<G1 as Group>::Scalar::zero()];
    for x in &circuit_primary.trace[0][1..34] {
        z0_primary.push(q_to_f(x));
    }
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    type C1 = R1CSCircuit;
    type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;
    let mut recursive_snark: RecursiveSNARK<G1, G2, C1, C2> = RecursiveSNARK::<G1, G2, C1, C2>::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        z0_primary.clone(),
        z0_secondary.clone(),
    );

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let num_steps = circuit_primary.trace.len();
    for i in 0..num_steps {
        print!("{:4}. {:51}", i, trace.code[i]);
        io::stdout().flush().unwrap();

        let start = Instant::now();
        let res = recursive_snark.prove_step(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            z0_primary.clone(),
            z0_secondary.clone(),
        );
        println!(
            "{:?}  {:0.2}%", start.elapsed(),
            ((i+1) as f32) * 100.0 / (num_steps as f32));

        assert!(res.is_ok());
    }

    print!("\nVerifying Proof... ");
    io::stdout().flush().unwrap();

    let start = Instant::now();
    let res = recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);
    assert!(res.is_ok());
    println!(
        "{} in {:?}",
        if res.is_ok() { "verified" } else { "NOT verified" },
        start.elapsed()
    );
}


#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Input file
    #[arg(name = "ELF File")]
    file: std::path::PathBuf,
}

fn main() -> nexus_riscv::Result<()> {
    let opts = Opts::parse();
    let mut vm = load_elf(&opts.file)?;

    let start = Instant::now();
    println!("Executing program...");
    io::stdout().flush().unwrap();

    let trace = eval(&mut vm, false, false)?;

    println!("Executed {} steps in {:?}", trace.trace.len(), start.elapsed());

    prove(&trace);
    Ok(())
}
