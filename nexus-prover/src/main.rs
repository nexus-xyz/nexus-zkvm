use clap::Parser;

use std::time::Instant;
use std::io::{self,Write};

use nexus_riscv::load_elf;
use nexus_riscv_circuit::{Trace,eval};

use nexus_prover::types::*;
use nexus_prover::error::*;
use nexus_prover::pp::*;
use nexus_prover::circuit::*;

fn prove(trace: Trace) -> Result<(), ProofError> {
    println!(
        "Synthesizing Circuit from R1CS with {} vars, {} constraints... ",
        trace.cs.a.len(),
        trace.cs.a[0].len()
    );
    let code = trace.code.clone();

    let t = Instant::now();
    let mut tr = Tr::new(trace);
    let pp = gen_pp(&tr)?;
    println!("Public setup complete. {:?}", t.elapsed());

    println!(
        "Primary circuit: {} vars, {} constraints.",
        pp.shape.num_vars,
        pp.shape.num_constraints
    );
    println!(
        "Secondary circuit: {} vars, {} constraints.",
        pp.shape_ec.num_vars,
        pp.shape_ec.num_constraints
    );

    let z_0 = tr.z0();
    let mut recursive_snark = RecursiveSNARK::new(&pp, &tr, &z_0);

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let num_steps = tr.steps();
    for i in 0..num_steps {
        print!("{:4}. {:51}", i, code[i]);
        io::stdout().flush().unwrap();

        let t = Instant::now();
        recursive_snark = RecursiveSNARK::prove_step(recursive_snark, &tr).unwrap();
        tr.advance();

        println!(
            "{:?}  {:0.2}%", t.elapsed(),
            ((i+1) as f32) * 100.0 / (num_steps as f32));
    }

    print!("\nVerifying Proof... ");
    io::stdout().flush().unwrap();
    let t = Instant::now();
    recursive_snark.verify(num_steps).expect("verify"); // TODO addd verify errors?
    println!("{:?}", t.elapsed());
    Ok(())
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Input file
    #[arg(name = "ELF File")]
    file: std::path::PathBuf,
}

fn main() -> Result<(), ProofError> {
    let opts = Opts::parse();
    let mut vm = load_elf(&opts.file)?;

    let start = Instant::now();
    println!("Executing program...");
    io::stdout().flush().unwrap();

    let trace = eval(&mut vm, false, false)?;

    println!("Executed {} steps in {:?}", trace.trace.len(), start.elapsed());

    prove(trace)
}
