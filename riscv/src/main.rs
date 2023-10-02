use nexus_riscv::*;

use clap::Parser;
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Show execution trace
    #[arg(short, long)]
    trace: bool,

    /// Input file
    #[arg(name = "ELF File")]
    file: std::path::PathBuf,
}

fn main() {
    let opts = Opts::parse();
    let t = Instant::now();
    match run_elf(&opts.file, opts.trace) {
        Ok(()) => (),
        Err(e) => println!("{e}"),
    }
    if opts.trace {
        let t = t.elapsed();
        println!("Elapsed time: {:?}", t);
    }
}
