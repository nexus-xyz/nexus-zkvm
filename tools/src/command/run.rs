use std::path::Path;

use clap::Args;

use crate::utils::{cargo, path_to_artifact};

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print instruction trace.
    #[arg(short)]
    pub verbose: bool,

    /// Build artifacts with the specified profile. "dev" is default.
    #[arg(long, default_value = "dev")]
    pub profile: String,

    /// Name of the bin target to run.
    #[arg(long)]
    pub bin: Option<String>,
}

pub fn handle_command(args: RunArgs) -> anyhow::Result<()> {
    let RunArgs { verbose, profile, bin } = args;

    run_vm(bin, verbose, &profile)
}

fn run_vm(bin: Option<String>, verbose: bool, profile: &str) -> anyhow::Result<()> {
    // build artifact
    cargo(None, ["build", "--profile", profile])?;

    let path = path_to_artifact(bin, profile)?;

    println!("running {}", &path.display());

    run_vm_with_elf_file(&path, verbose)
}

pub fn run_vm_with_elf_file(path: &Path, verbose: bool) -> anyhow::Result<()> {
    let opts = nexus_api::nvm::VMOpts {
        k: 1,
        machine: None,
        file: Some(path.into()),
    };

    nexus_api::nvm::run_vm::<nexus_api::nvm::memory::Paged>(&opts, verbose).map_err(Into::into)
}
