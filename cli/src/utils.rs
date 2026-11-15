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

/// Runs `cargo new` for a package built with the pinned guest toolchain (Rust 1.77).
///
/// The edition and `rust-version` are set explicitly: a newer host cargo would otherwise
/// default to edition 2024 and write a version 4 lockfile, neither of which Rust 1.77 can read.
/// `.cargo/config.toml` also asks a newer cargo to pick dependency versions that support 1.77.
pub fn cargo_new(path: &str) -> anyhow::Result<()> {
    cargo(None, ["new", "--edition", "2021", path])?;
    let manifest = Path::new(path).join("Cargo.toml");
    let toml = std::fs::read_to_string(&manifest)?;
    let toml = toml.replacen(
        "edition = \"2021\"\n",
        "edition = \"2021\"\nrust-version = \"1.77\"\n",
        1,
    );
    std::fs::write(manifest, toml)?;
    let config = Path::new(path).join(".cargo");
    std::fs::create_dir_all(&config)?;
    std::fs::write(config.join("config.toml"), RESOLVER_CONFIG)?;
    Ok(())
}

/// Pick dependency versions compatible with each package's `rust-version`. Cargo before 1.84
/// ignores this setting.
pub const RESOLVER_CONFIG: &str = "[resolver]\nincompatible-rust-versions = \"fallback\"\n";

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
