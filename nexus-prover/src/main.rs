use clap::{Parser, Subcommand};

use std::time::Instant;
use std::io::{self,Write};

use nexus_riscv::load_elf;
use nexus_riscv_circuit::{Trace,eval};

use nexus_prover::types::*;
use nexus_prover::error::*;
use nexus_prover::pp::*;
use nexus_prover::circuit::*;

fn run(file: &str) -> Result<Trace, ProofError> {
    let mut vm = load_elf(&std::path::PathBuf::from(file))?;

    let start = Instant::now();
    println!("Executing program...");
    io::stdout().flush().unwrap();

    let trace = eval(&mut vm, false, false)?;

    println!("Executed {} steps in {:?}", trace.trace.len(), start.elapsed());
    Ok(trace)
}

fn prove(pp: PP<Tr>, trace: Trace) -> Result<(), ProofError> {
    let code = trace.code.clone();
    let mut tr = Tr::new(trace);
    let z_0 = tr.z0();
    let mut recursive_snark = RecursiveSNARK::new(&pp, &z_0);

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
struct Opts {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate public parameters file
    Gen {
        /// private parameters file
        #[arg(short='p',long="private-params",default_value="nexus-public.zst")]
        pp_file: String,
    },

    /// Prove execution of program
    Prove {
        /// generate public parameters (ignore files)
        #[arg(short)]
        gen: bool,

        /// private parameters file
        #[arg(short='p',long="private-params",default_value="nexus-public.zst")]
        pp_file: String,

        /// Input file
        #[arg(name = "ELF File")]
        file: String,
    },
}
use Command::*;

fn main() -> Result<(), ProofError> {
    let opts = Opts::parse();

    match opts.command {
        Gen { pp_file } => {
            println!("Generating public parameters to {pp_file}...");
            let pp = gen_vm_pp()?;
            save_pp(pp, &pp_file)
        },
        Prove { gen, pp_file, file } => {
            let pp = if gen {
                println!("Generating public parameters...");
                gen_vm_pp()?
            } else {
                println!("Loading public parameters from {pp_file}...");
                load_pp(&pp_file)?
            };
            let trace = run(&file)?;
            prove(pp, trace)
        },
    }
}
