use std::path::PathBuf;

use cargo_metadata::MetadataCommand;
use clap::Parser;

use nexus_tools_dev::{command::dev::common_impl::run, setup_logger};

#[derive(Debug, Parser)]
pub struct Args {
    path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let _guard = setup_logger();

    let Args { path } = Args::parse();
    let verbose = false;

    let path = if path.is_absolute() {
        path
    } else {
        let md = MetadataCommand::new().exec()?;

        md.workspace_root.as_std_path().join(path)
    };

    run::run_vm_with_elf_file(&path, verbose)
}
