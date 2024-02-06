use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context;
use cargo_metadata::MetadataCommand;

pub fn cargo<I, S>(dir: Option<&Path>, args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_err| "cargo".into());

    let status = Command::new(cargo_bin)
        .args(args)
        .current_dir(dir.unwrap_or(Path::new(".")))
        .status()?;
    if !status.success() {
        anyhow::bail!("cargo didn't exit successfully: {status}")
    }
    Ok(())
}

/// Checks if the binary is part of cargo manifest and returns path to the build artifact.
pub fn path_to_artifact(bin: Option<String>, release: bool) -> anyhow::Result<PathBuf> {
    let md = MetadataCommand::new().exec()?;

    let pkg = md.root_package().context("package root not found")?;
    let bin_targets: Vec<String> = pkg
        .targets
        .iter()
        .filter(|target| target.is_bin())
        .map(|target| target.name.clone())
        .collect();

    let mut path = PathBuf::from(&md.target_directory);
    path.push("riscv32i-unknown-none-elf");
    if release {
        path.push("release");
    } else {
        path.push("debug");
    }

    if bin_targets.len() == 1 {
        path.push(&bin_targets[0]);
        return Ok(path);
    }

    let name = bin
        .or(pkg.default_run.clone())
        .with_context(|| format!("--bin must be one of {}", bin_targets.join(", ")))?;

    for target in &bin_targets {
        if target == &name {
            path.push(name);
            return Ok(path);
        }
    }
    anyhow::bail!("target not found")
}
