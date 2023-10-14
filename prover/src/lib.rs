#[cfg(feature = "ns")]
pub mod null_schemes;
pub mod types;
pub mod error;
pub mod circuit;
pub mod pp;

use crate::types::*;
use crate::error::*;
use crate::circuit::*;
use crate::pp::*;

use std::time::Instant;
use std::io::{self, Write};
use nexus_riscv::{VMOpts, load_vm};
use nexus_riscv_circuit::{Trace, eval};

pub fn gen_to_file(k: usize, par: bool, pp_file: &str) -> Result<(), ProofError> {
    println!("Generating public parameters to {pp_file}...");
    if par {
        let pp: ParPP<Tr> = gen_vm_pp(k)?;
        save_pp(pp, pp_file)
    } else {
        let pp: SeqPP<Tr> = gen_vm_pp(k)?;
        save_pp(pp, pp_file)
    }
}

fn estimate_size(tr: &Trace) -> usize {
    use std::mem::size_of_val as sizeof;
    sizeof(&tr.trace)
        + sizeof(&tr.trace[0])
        + sizeof(&tr.trace[0][0]) * tr.trace[0].len() * tr.trace.len()
}

pub fn run(opts: &VMOpts) -> Result<Trace, ProofError> {
    let mut vm = load_vm(opts)?;

    let start = Instant::now();
    println!("Executing program...");
    io::stdout().flush().unwrap();

    let trace = eval(&mut vm, opts.k, false)?;

    println!(
        "Executed {} instructions in {:?}. {} bytes used by trace.",
        trace.trace.len(),
        start.elapsed(),
        estimate_size(&trace)
    );
    Ok(trace)
}

pub fn prove_seq(pp: SeqPP<Tr>, trace: Trace) -> Result<(), ProofError> {
    let k = trace.k;
    let icount = k * trace.trace.len();
    let tr = Tr::new(trace);
    let z_0 = tr.input(0);
    let mut proof = IVCProof::new(&pp, &z_0);

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let start = Instant::now();

    let num_steps = tr.steps();
    for i in 0..num_steps {
        print!("{:4}. {:51}", i, format!("{} instructions...", k));
        io::stdout().flush().unwrap();

        let t = Instant::now();
        proof = IVCProof::prove_step(proof, &tr).unwrap();

        println!(
            "{:?}  {:0.2}%",
            t.elapsed(),
            ((i + 1) as f32) * 100.0 / (num_steps as f32)
        );
    }
    println!(
        "\nProof Complete: {:.2} instructions / second",
        icount as f64 / start.elapsed().as_secs_f64()
    );

    print!("\nVerifying Proof... ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    proof.verify(num_steps).expect("verify"); // TODO add verify errors?
    println!("{:?}", t.elapsed());
    Ok(())
}

pub fn prove_par(pp: ParPP<Tr>, trace: Trace) -> Result<(), ProofError> {
    let k = trace.k;
    let tr = Tr::new(trace);

    let steps = tr.steps().next_power_of_two();
    println!("\nproving {steps} of {} base steps", tr.steps());
    println!("proving even steps...");

    let start = Instant::now();

    let mut vs = (0..steps)
        .step_by(2)
        .map(|i| {
            print!("leaf step {i}... ");
            io::stdout().flush().unwrap();
            let t = Instant::now();
            let v = PCDNode::prove_step(&pp, &tr, i, &tr.input(i))?;
            println!("{:?}", t.elapsed());
            Ok(v)
        })
        .collect::<Result<Vec<_>, ProofError>>()?;

    loop {
        if vs.len() == 1 {
            break;
        }
        println!("proving {} vertex steps", vs.len() / 2);
        vs = vs
            .chunks(2)
            .map(|ab| {
                print!("vertex step ...  ");
                io::stdout().flush().unwrap();
                let t = Instant::now();
                let c = PCDNode::prove_from(&pp, &tr, &ab[0], &ab[1])?;
                println!("{:?}", t.elapsed());
                Ok(c)
            })
            .collect::<Result<Vec<_>, ProofError>>()?;
    }

    println!(
        "\nProof Complete: {:.2} instructions / second",
        (k * tr.steps()) as f64 / start.elapsed().as_secs_f64()
    );

    print!("\nVerifying root...  ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    vs[0].verify(&pp)?;
    println!("{:?}", t.elapsed());
    Ok(())
}
