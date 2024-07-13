use std::path::PathBuf;

use clap::Parser;

use nexus_cli::command::run;

#[derive(Debug, Parser)]
pub struct Args {
    path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let Args { path } = Args::parse();
    let verbose = false;

    run::run_vm_with_elf_file(&path, verbose)
}
