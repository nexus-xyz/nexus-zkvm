use nexus_riscv::{Result, load_elf};
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

    /// Input file
    #[arg(name = "ELF File")]
    file: std::path::PathBuf,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let mut vm = load_elf(&opts.file)?;

    let start = Instant::now();
    let trace = eval(&mut vm, opts.trace, opts.check)?;
    println!("Executed {} steps in {:?}", trace.trace.len(), start.elapsed());
    Ok(())
}
