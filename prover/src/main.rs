use clap::{Parser, Subcommand};

use std::time::Instant;
use std::io::{self, Write};

use nexus_riscv::{VMOpts, load_vm};
use nexus_riscv_circuit::{Trace, eval};

use nexus_prover::types::*;
use nexus_prover::error::*;
use nexus_prover::pp::*;
use nexus_prover::circuit::*;

fn estimate_size(tr: &Trace) -> usize {
    use std::mem::size_of_val as sizeof;
    sizeof(&tr.trace)
        + sizeof(&tr.trace[0])
        + sizeof(&tr.trace[0][0]) * tr.trace[0].len() * tr.trace.len()
}

fn run(opts: &VMOpts) -> Result<Trace, ProofError> {
    let mut vm = load_vm(opts)?;

    let start = Instant::now();
    println!("Executing program...");
    io::stdout().flush().unwrap();

    let trace = eval(&mut vm, opts.k, false, false)?;

    println!(
        "Executed {} instructions in {:?}. {} bytes used by trace.",
        trace.trace.len(),
        start.elapsed(),
        estimate_size(&trace)
    );
    Ok(trace)
}

fn prove(pp: PP<Tr>, trace: Trace) -> Result<(), ProofError> {
    let k = trace.k;
    let code = trace.code.clone();
    let mut tr = Tr::new(trace);
    let z_0 = tr.z0();
    let mut recursive_snark = RecursiveSNARK::new(&pp, &z_0);

    println!("\nProving Execution Trace:");
    println!("step. {:7} {:8} {:32} time", "pc", "mem[pc]", "inst");

    let start = Instant::now();

    let num_steps = tr.steps();
    let mut j = 0;
    for i in 0..num_steps {
        if k < 5 {
            for x in 0..k {
                print!("{:4}. {:51}", j, code[j]);
                j += 1;
                if x < k - 1 {
                    println!();
                }
            }
        } else {
            print!("{:4}. {:51}", i, format!("{} instructions...", k));
        }
        io::stdout().flush().unwrap();

        let t = Instant::now();
        recursive_snark = RecursiveSNARK::prove_step(recursive_snark, &tr).unwrap();
        tr.advance();

        println!(
            "{:?}  {:0.2}%",
            t.elapsed(),
            ((i + 1) as f32) * 100.0 / (num_steps as f32)
        );
    }
    println!(
        "\nExecution Complete: {:.2} instructions / second",
        code.len() as f64 / start.elapsed().as_secs_f64()
    );

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
        /// Instructions per step
        #[arg(short, name = "k", default_value = "1")]
        k: usize,

        /// private parameters file
        #[arg(
            short = 'p',
            long = "private-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,
    },

    /// Prove execution of program
    Prove {
        /// generate public parameters (ignore files)
        #[arg(short)]
        gen: bool,

        /// private parameters file
        #[arg(
            short = 'p',
            long = "private-params",
            default_value = "nexus-public.zst"
        )]
        pp_file: String,

        #[command(flatten)]
        vm: VMOpts,
    },
}
use Command::*;

fn main() -> Result<(), ProofError> {
    let opts = Opts::parse();

    match opts.command {
        Gen { k, pp_file } => {
            println!("Generating public parameters to {pp_file}...");
            let pp = gen_vm_pp(k)?;
            save_pp(pp, &pp_file)
        }
        Prove { gen, pp_file, vm } => {
            let t = std::time::Instant::now();
            let pp = if gen {
                println!("Generating public parameters...");
                gen_vm_pp(vm.k)?
            } else {
                println!("Loading public parameters from {pp_file}...");
                load_pp(&pp_file)?
            };
            println!("Got public parameters in {:?}", t.elapsed());
            let trace = run(&vm)?;
            prove(pp, trace)
        }
    }
}
