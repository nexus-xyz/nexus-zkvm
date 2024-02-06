use std::{ffi::OsString, path::Path};

use nexus_config::{Config, VmConfig};

use crate::{
    command::{common::RunArgs, dev::compile_env_configs},
    utils::{cargo, path_to_artifact},
};

pub fn handle_command(args: RunArgs) -> anyhow::Result<()> {
    let RunArgs {
        verbose,
        release,
        bin,
    } = args;

    run_vm(bin, verbose, release)
}

fn run_vm(bin: Option<String>, verbose: bool, release: bool) -> anyhow::Result<()> {
    // build the artifact
    if release {
        cargo(None, &["build", "--release"])?;
    } else {
        cargo(None, &["build"])?;
    }

    let path = path_to_artifact(bin, release)?;

    run_vm_with_elf_file(&path, verbose)
}

pub fn run_vm_with_elf_file(path: &Path, verbose: bool) -> anyhow::Result<()> {
    // <path> [--trace]
    let mut vm_opts = vec![path.as_os_str().to_os_string()];
    if verbose {
        vm_opts.push("--trace".into());
    }

    let mut cargo_opts: Vec<OsString> = ["run", "-p", "nexus-riscv"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut vm_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
