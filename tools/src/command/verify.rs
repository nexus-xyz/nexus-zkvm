use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::Context;
use nexus_prover::types::PCDNode;
use nexus_tools_dev::command::common::{public_params::format_params_file, VerifyArgs};
use ark_serialize::CanonicalDeserialize;
use nexus_config::vm as vm_config;

use crate::{LOG_TARGET, command::DEFAULT_K};

pub fn handle_command(args: VerifyArgs) -> anyhow::Result<()> {
    let VerifyArgs { pp_file, k, file } = args;

    verify_proof(&file, k.unwrap_or(DEFAULT_K), pp_file)
}

fn verify_proof(path: &Path, k: usize, pp_file: Option<PathBuf>) -> anyhow::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let proof: nexus_network::api::Proof = serde_json::from_reader(reader)?;

    let serialized_proof = proof.proof.context("invalid proof object")?;
    let root = PCDNode::deserialize_compressed(serialized_proof.as_slice())?;

    let path = pp_file
        .as_deref()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| format_params_file(vm_config::NovaImpl::Parallel, k));
    let state = nexus_prover::pp::gen_or_load(false, k, &path)?;

    match root.verify(&state) {
        Ok(_) => {
            tracing::info!(
                target: LOG_TARGET,
                "Proof is valid",
            );
        }
        Err(err) => {
            tracing::error!(
                target: LOG_TARGET,
                err = ?err,
                "Proof is invalid",
            );
            std::process::exit(1);
        }
    }
    Ok(())
}
