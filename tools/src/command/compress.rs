use anyhow::Context;
use std::io;

use crate::{
    command::{cache_path, spartan_key::spartan_setup},
    LOG_TARGET,
};
use nexus_config::{vm as vm_config, Config};
use nexus_tools_dev::command::common::{
    compress::CompressArgs, public_params::format_params_file, spartan_key::SetupArgs,
};

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
