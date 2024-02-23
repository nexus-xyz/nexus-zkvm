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
    } = args;

    // make sure configs are compiled
    compile_env_configs(false)?;
    let vm_config = VmConfig::from_env()?;

    verify_proof(&file, vm_config.k, pp_file)
}

fn verify_proof(_path: &Path, _k: usize, _pp_file: Option<PathBuf>) -> anyhow::Result<()> {
    // This command should be part of `nexus-prover`, which doesn't support decoding
    // proofs from the network.
    //
    // TODO: extract encoding into a separate crate.
    unimplemented!()
}
