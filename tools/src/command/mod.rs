use std::path::PathBuf;

use nexus_config::{Config, MiscConfig};
use nexus_tools_dev::{command::common::Command as CommonCommand, Command};

pub mod compress;
pub mod new;
pub mod prove;
pub mod public_params;
pub mod request;
pub mod run;
pub mod spartan_key;
pub mod verify;

mod jolt;

/// Default environment variables for prover configuration.
const ENV: &str = r#"
NEXUS_VM_K=16
NEXUS_VM_PROVER=nova-seq
"#;

pub fn handle_command(cmd: Command) -> anyhow::Result<()> {
    #![allow(irrefutable_let_patterns)] // rust-analyzer may give a false warning in a workspace.

    dotenvy::from_read(ENV.as_bytes()).expect("env must be valid");

    let Command::Common(cmd) = cmd else { unreachable!() };
    match cmd {
        CommonCommand::New(args) => new::handle_command(args),
        CommonCommand::Run(args) => run::handle_command(args),
        CommonCommand::Prove(args) => prove::handle_command(args),
        CommonCommand::Request(args) => request::handle_command(args),
        CommonCommand::Verify(args) => verify::handle_command(args),
        CommonCommand::PublicParams(args) => public_params::handle_command(args),
        CommonCommand::Compress(args) => compress::handle_command(args),
        CommonCommand::SpartanKey(args) => spartan_key::handle_command(args),
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
    use nexus_config::{Config, VmConfig};

    #[test]
    fn env_config() {
        dotenvy::from_read(ENV.as_bytes()).unwrap();
        <VmConfig as Config>::from_env().unwrap();
    }
}
