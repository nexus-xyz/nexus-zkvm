use nexus_vm::{memory::trie::MerkleTrie, run_vm, VMOpts};

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
    match run_vm::<MerkleTrie>(&opts.vm, opts.trace) {
        Ok(()) => (),
        Err(e) => println!("{e}"),
    }
}
