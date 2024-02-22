//! Development commands should only be available and used inside the workspace.
//!
//! To avoid recompiling Cli, it shouldn't depend on crates from the workspace, and instead
//! run binaries with cargo.

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Subcommand;

use nexus_config::{Config, MiscConfig};

macro_rules! cargo_manifest_dir_path {
    () => {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    };
}

mod clean;
mod config;
mod node;

pub mod common_impl;

pub(crate) use config::compile_to_env_from_bases as compile_env_configs;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Remove compiled configs and public parameters cache.
    Clean,
    /// Configuration management.
    Config(config::ConfigArgs),
    /// Run the network node.
    Node(node::NodeArgs),
}

pub(crate) fn handle_command(cmd: Command) -> anyhow::Result<()> {
    match cmd {
        Command::Config(args) => config::handle_command(args),
        Command::Clean => clean::handle_command(),
        Command::Node(args) => node::handle_command(args),
    }
}

/// Creates and returns the cache path.
pub(crate) fn cache_path() -> anyhow::Result<PathBuf> {
    let path = if let Ok(config) = MiscConfig::from_env() {
        config.cache
    } else {
        // default to using workspace target directory
        let manifest_path = cargo_manifest_dir_path!();
        manifest_path
            .parent()
            .and_then(Path::parent)
            .context("parent directory not found")?
            .join("target/nexus-cache")
    };
    std::fs::create_dir_all(&path)?;

    Ok(path)
}
