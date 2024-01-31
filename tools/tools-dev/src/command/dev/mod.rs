use std::path::PathBuf;

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
mod public_params;

pub mod common_impl;

pub(crate) use config::compile_to_env_from_bases as compile_env_configs;

#[derive(Debug, Subcommand)]
pub enum Command {
    Clean,
    Config(config::ConfigArgs),
    #[clap(name = "pp")]
    PublicParams(public_params::PublicParamsArgs),

    Node(node::NodeArgs),
}

pub(crate) fn handle_command(cmd: Command) -> anyhow::Result<()> {
    match cmd {
        Command::Config(args) => config::handle_command(args),
        Command::PublicParams(args) => public_params::handle_command(args),
        Command::Clean => clean::handle_command(),
        Command::Node(args) => node::handle_command(args),
    }
}

pub(crate) fn cache_path() -> anyhow::Result<PathBuf> {
    let path = MiscConfig::from_env()?.cache_path;
    std::fs::create_dir_all(&path)?;

    Ok(path)
}
