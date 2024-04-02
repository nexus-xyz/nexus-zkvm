use std::{fs, path::PathBuf, io::Write};

use anyhow::Context;
use clap::Args;

use crate::utils::cargo;

#[derive(Debug, Args)]
pub struct NewArgs {
    #[arg(name = "path")]
    pub path: PathBuf,
}

pub fn handle_command(args: NewArgs) -> anyhow::Result<()> {
    let path = args.path;

    setup_crate(path)
}

fn setup_crate(path: PathBuf) -> anyhow::Result<()> {
    let path_str = path.to_str().context("path is not a valid UTF-8 string")?;

    // run cargo to setup project
    cargo(None, ["new", path_str])?;
    cargo(
        Some(&path),
        [
            "add",
            "--git",
            "https://github.com/nexus-xyz/nexus-zkvm.git",
            "nexus-rt",
        ],
    )?;

    let mut fp = fs::OpenOptions::new()
        .append(true)
        .open(path.join("Cargo.toml"))?;

    writeln!(fp, concat!("\n",
                         "[profile.release-unoptimized]\n",
                         "inherits = \"release\"\n",
                         "opt-level = 0\n")
    )?;

    // .cargo/config
    let config_path = path.join(".cargo");
    fs::create_dir_all(&config_path)?;
    fs::write(config_path.join("config"), TEMPLATE_CARGO_CONFIG)?;

    // src/main.rs
    fs::write(path.join("src/main.rs"), TEMPLATE_SRC_MAIN)?;

    Ok(())
}

macro_rules! examples_dir {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples")
    };
}

const TEMPLATE_CARGO_CONFIG: &str = include_str!(concat!(examples_dir!(), "/.cargo/config"));
const TEMPLATE_SRC_MAIN: &str = include_str!(concat!(examples_dir!(), "/src/main.rs"));
