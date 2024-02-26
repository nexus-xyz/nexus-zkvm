use nexus_riscv::*;

use clap::Parser;

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
    match run_vm(&opts.vm, opts.trace) {
        Ok(()) => (),
        Err(e) => println!("{e}"),
    }
}
