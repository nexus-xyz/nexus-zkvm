use nexus_riscv::*;

use clap::Parser;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Show execution trace
    #[arg(short, long)]
    trace: bool,

    #[command(flatten)]
    vm: VMOpts,
}

fn main() {
    let opts = Opts::parse();

    let t = Instant::now();
    match run_vm(&opts.vm, opts.trace) {
        Ok(()) => {
            if opts.trace {
                println!("Elapsed time: {:?}", t.elapsed());
            }
        }
        Err(e) => println!("{e}"),
    }
}
