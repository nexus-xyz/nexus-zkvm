use anyhow::Context;
use std::io;

use crate::{command::spartan_key::spartan_setup, LOG_TARGET};
use nexus_prover::error::ProofError;
use nexus_tools_dev::command::common::{compress::CompressArgs, spartan_key::SetupArgs};

pub fn handle_command(args: CompressArgs) -> anyhow::Result<()> {
    compress_proof(args)
}

pub fn compress_proof(args: CompressArgs) -> anyhow::Result<()> {
    let pp_file = args.pp_file;
    if !pp_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            pp_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    };
    let pp_file_str = pp_file.to_str().context("path is not valid utf8")?;

    tracing::info!(
        target: LOG_TARGET,
        path =?pp_file,
        "Reading the Nova public parameters",
    );

    let pp = nexus_prover::pp::load_pp(pp_file_str)?;

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
    } else if let Some(srs_file) = args.srs_file {
        spartan_setup(SetupArgs {
            force: false,
            pp_file,
            srs_file,
            path: None,
        })?
    } else {
        tracing::error!(
            target: LOG_TARGET,
            "SRS file must be provided to generate the Spartan key",
        );
        return Err(ProofError::MissingSRS.into());
    };
    let key_file_str = key_file.to_str().context("path is not valid utf8")?;
    let key = nexus_prover::key::gen_or_load_key(false, key_file_str, None, None)?;

    let proof_file = args.proof_file;
    if !proof_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            proof_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    };
    let proof = nexus_prover::load_proof(&proof_file)?;

    let current_dir = std::env::current_dir()?;
    let compressed_proof_path = current_dir.join("nexus-proof-compressed");

    let compressed_proof = nexus_prover::compress(&pp, &key, proof)?;

    nexus_prover::save_proof(compressed_proof, &compressed_proof_path)?;

    Ok(())
}
