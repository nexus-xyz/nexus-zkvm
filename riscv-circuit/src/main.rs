use nexus_riscv::{Result, VMOpts, load_vm};
use nexus_riscv_circuit::*;

use clap::Parser;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Show execution trace
    #[arg(short, long)]
    trace: bool,

    /// Check each witness during execution (debugging)
    #[arg(short, long)]
    check: bool,

    #[command(flatten)]
    vm: VMOpts,
}

fn run(opts: &Opts) -> Result<Trace> {
    let mut vm = load_vm(&opts.vm)?;
    eval(&mut vm, opts.vm.k, opts.trace, opts.check)
}

fn main() {
    let opts = Opts::parse();
    let start = Instant::now();
    match run(&opts) {
        Err(e) => {
            println!("{}", e);
        }
        Ok(trace) => {
            println!("Executed {} steps in {:?}", trace.trace.len(), start.elapsed());
        }
    }
}
