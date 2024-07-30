use chrono::{Datelike, Local, Timelike};
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
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let flamegraph = std::env::var("FLAMEGRAPH").map_or(false, |value| value == "1");
    let mut command = if flamegraph {
        let samply_bin = std::env::var("SAMPLY").unwrap_or_else(|_| "samply".into());
        let mut cmd = Command::new(samply_bin);

        let now = Local::now();
        let output_file = format!(
            "profile_{:04}{:02}{:02}_{:02}{:02}.json",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute()
        );
        cmd.args([
            "record",
            "--save-only",
            "--output",
            &output_file,
            &cargo_bin,
        ]);
        cmd
    } else {
        Command::new(cargo_bin)
    };

    let status = command
        .args(args)
        .current_dir(dir.unwrap_or_else(|| Path::new(".")))
        .status()?;

    if !status.success() {
        anyhow::bail!("cargo didn't exit successfully: {status}")
    }
    Ok(())
}

/// Checks if the binary is part of cargo manifest and returns path to the build artifact.
pub fn path_to_artifact(bin: Option<String>, mut profile: &str) -> anyhow::Result<PathBuf> {
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

    // "debug" profile is reserved.
    if profile == "dev" {
        profile = "debug";
    }
    path.push(profile);

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
