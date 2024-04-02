use std::path::Path;

use nexus_tools_dev::{
    command::common::RunArgs,
    utils::{cargo, path_to_artifact},
};

pub fn handle_command(args: RunArgs) -> anyhow::Result<()> {
    let RunArgs { verbose, release, profile, bin } = args;
    let profile = if release {
        "release".to_string()
    } else {
        profile
    };

    run_vm(bin, verbose, &profile)
}

fn run_vm(bin: Option<String>, verbose: bool, profile: &str) -> anyhow::Result<()> {
    // build artifact
    cargo(None, ["build", "--profile", profile])?;

    let path = path_to_artifact(bin, profile)?;

    run_vm_with_elf_file(&path, verbose)
}

pub fn run_vm_with_elf_file(path: &Path, verbose: bool) -> anyhow::Result<()> {
    let opts = nexus_riscv::VMOpts {
        k: 1,
        nop: None,
        loopk: None,
        machine: None,
        file: Some(path.into()),
    };

    nexus_riscv::run_vm(&opts, verbose).map_err(Into::into)
}
