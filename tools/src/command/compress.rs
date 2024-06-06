use std::{io, path::PathBuf};

use anyhow::Context;
use clap::Args;

use nexus_config::{vm as vm_config, Config};

use super::{public_params::format_params_file, spartan_key::SetupArgs};
use crate::{
    command::{cache_path, spartan_key::spartan_setup},
    LOG_TARGET,
};
use super::prove::{save_proof, TERMINAL_MODE};
use nexus_api::config::{vm as vm_config, Config};

#[derive(Debug, Args)]
pub struct CompressArgs {
    /// Number of vm instructions per fold
    #[arg(short, name = "k")]
    pub k: Option<usize>,

    /// Spartan key file
    #[arg(long = "key")]
    pub key_file: Option<PathBuf>,

    /// public parameters file; only needed if generating a new Spartan key
    #[arg(short = 'p', long = "public-params")]
    pub pp_file: Option<PathBuf>,

    /// srs file; only needed if generating a new Spartan key
    #[arg(short = 's', long = "structured-reference-string")]
    pub srs_file: Option<PathBuf>,

    /// File containing uncompressed proof
    #[arg(short = 'f', long = "proof-file")]
    pub proof_file: PathBuf,
}

pub fn handle_command(args: CompressArgs) -> anyhow::Result<()> {
    compress_proof(args)
}

pub fn compress_proof(args: CompressArgs) -> anyhow::Result<()> {
    let vm_config = vm_config::VmConfig::from_env()?;
    let k = args.k.unwrap_or(vm_config.k);

    let pp_file = match args.pp_file {
        None => {
            let nova_impl = vm_config::NovaImpl::ParallelCompressible;

            let pp_file_name = format_params_file(nova_impl, k);
            let cache_path = cache_path()?;

            cache_path.join(pp_file_name)
        }
        Some(path) => path,
    };
    if !pp_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            pp_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    };
    tracing::info!(
        target: LOG_TARGET,
        path =?pp_file,
        "Reading the Nova public parameters",
    );
    let pp_file_str = pp_file.to_str().context("path is not valid utf8")?;

    let pp = nexus_api::prover::nova::pp::load_pp(pp_file_str)?;

    let key_file = if let Some(path) = args.key_file {
        // return early if the path was explicitly specified and doesn't exist
        if !path.try_exists()? {
            tracing::error!(
                target: LOG_TARGET,
                "path {} was not found",
                path.display(),
            );
            return Err(io::Error::from(io::ErrorKind::NotFound).into());
        }
        path
    } else {
        spartan_setup(SetupArgs {
            path: None,
            force: false,
            k: Some(k),
            pp_file: Some(pp_file),
            srs_file: args.srs_file,
        })?
    };
    let key_file_str = key_file.to_str().context("path is not valid utf8")?;
    let key = nexus_api::prover::nova::key::load_key(key_file_str)?;

    let proof_file = args.proof_file;
    if !proof_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            proof_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    };
    let proof = nexus_api::prover::nova::load_proof(&proof_file)?;

    let current_dir = std::env::current_dir()?;
    let compressed_proof_path = current_dir.join("nexus-proof-compressed");

    let compressed_proof = compress(&pp, &key, proof)?;

    save_proof(compressed_proof, &compressed_proof_path)?;

    Ok(())
}

fn load_proof<P: CanonicalDeserialize>(path: &Path) -> Result<P, ProofError> {
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut context = term.context("Loading").on_step(|_step| "proof".into());
    let _guard = context.display_step();

    let proof = nexus_api::prover::nova::load_proof(path);

    Ok(proof)
}

fn compress(
    compression_pp: &ComPP,
    key: &SpartanKey,
    node: ComPCDNode,
) -> Result<ComProof, ProofError> {
    let mut term = nexus_tui::TerminalHandle::new(TERMINAL_MODE);
    let mut term_ctx = term
        .context("Compressing")
        .on_step(|_step| "the proof".into());
    let _guard = term_ctx.display_step();

    let proof = nexus_api::prover::nova::compress(compression_pp, key, node);

    Ok(proof)
}
