use clap::Subcommand;
use std::path::PathBuf;

use nexus_core::config::{Config, MiscConfig};

use super::ENV;

pub mod compress;
pub mod new;
pub mod prove;
pub mod public_params;
pub mod request;
pub mod run;
pub mod spartan_key;
pub mod verify;

mod jolt;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new Nexus package at <path>.
    New(new::NewArgs),
    /// Run a binary with the Nexus VM.
    Run(run::RunArgs),
    /// Compute proof of program execution.
    Prove(prove::ProveArgs),
    /// Request proof status from the network; download it if it's finished.
    Request(request::RequestArgs),
    /// Verify the proof.
    Verify(verify::VerifyArgs),
    /// Nova public parameters management.
    #[clap(name = "pp")]
    PublicParams(public_params::PublicParamsArgs),
    /// Spartan key management.
    SpartanKey(spartan_key::SpartanSetupArgs),
    /// Compress a Nova proof.
    Compress(compress::CompressArgs),
}

pub fn handle_command(cmd: Command) -> anyhow::Result<()> {
    dotenvy::from_read(ENV.as_bytes()).expect("env must be valid");

    match cmd {
        Command::New(args) => new::handle_command(args),
        Command::Run(args) => run::handle_command(args),
        Command::Prove(args) => prove::handle_command(args),
        Command::Request(args) => request::handle_command(args),
        Command::Verify(args) => verify::handle_command(args),
        Command::PublicParams(args) => public_params::handle_command(args),
        Command::Compress(args) => compress::handle_command(args),
        Command::SpartanKey(args) => spartan_key::handle_command(args),
    }
}

/// Creates and returns the cache path.
pub(crate) fn cache_path() -> anyhow::Result<PathBuf> {
    let path = if let Ok(config) = MiscConfig::from_env() {
        config.cache
    } else {
        // default to using project target directory
        let md = cargo_metadata::MetadataCommand::new().exec()?;
        let target_dir = md.target_directory;
        target_dir.as_std_path().join("nexus-cache")
    };
    std::fs::create_dir_all(&path)?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::config::{vm::VmConfig, Config};

    #[test]
    fn env_config() {
        dotenvy::from_read(ENV.as_bytes()).unwrap();
        <VmConfig as Config>::from_env().unwrap();
    }
}
