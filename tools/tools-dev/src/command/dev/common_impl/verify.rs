use std::path::{Path, PathBuf};

use nexus_config::{Config, VmConfig};

use crate::command::{
    common::{prove::LocalProveArgs, VerifyArgs},
    dev::compile_env_configs,
};

pub fn handle_command(args: VerifyArgs) -> anyhow::Result<()> {
    let VerifyArgs {
        file,
        prover_args: LocalProveArgs { pp_file, .. },
        compressed,
        key_file,
    } = args;

    // make sure configs are compiled
    compile_env_configs(false)?;
    let vm_config = VmConfig::from_env()?;

    if compressed {
        verify_proof_compressed(&file, vm_config.k, pp_file, key_file)
    } else {
        verify_proof(&file, vm_config.k, pp_file)
    }
}

fn verify_proof(_path: &Path, _k: usize, _pp_file: Option<PathBuf>) -> anyhow::Result<()> {
    // This command should be part of `nexus-prover`, which doesn't support decoding
    // proofs from the network.
    //
    // TODO: extract encoding into a separate crate.
    unimplemented!()
}

fn verify_proof_compressed(
    _path: &Path,
    _k: usize,
    _pp_file: Option<PathBuf>,
    _key_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    // This command should be part of `nexus-prover`, which doesn't support decoding
    // proofs from the network.
    //
    // TODO: extract encoding into a separate crate.
    unimplemented!()
}
