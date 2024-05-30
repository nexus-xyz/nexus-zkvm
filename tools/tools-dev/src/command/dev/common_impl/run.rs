use std::{ffi::OsString, path::Path};

use crate::{
    command::common::RunArgs,
    utils::{cargo, path_to_artifact},
};

pub fn handle_command(args: RunArgs) -> anyhow::Result<()> {
    let RunArgs { verbose, profile, bin } = args;

    run_vm(bin, verbose, &profile)
}

fn run_vm(bin: Option<String>, verbose: bool, profile: &str) -> anyhow::Result<()> {
    // build artifact
    cargo(None, ["build", "--profile", profile])?;

    let path = path_to_artifact(bin, profile)?;

    run_vm_with_elf_file(&path, verbose)
}

pub fn run_vm_with_elf_file(path: &Path, verbose: bool) -> anyhow::Result<()> {
    // <path> [--trace]
    let mut vm_opts = vec![path.as_os_str().to_os_string()];
    if verbose {
        vm_opts.push("--trace".into());
    }

    let mut cargo_opts: Vec<OsString> = ["run", "-p", "nexus-vm"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut vm_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
