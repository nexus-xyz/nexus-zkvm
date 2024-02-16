use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;
use ark_serialize::CanonicalSerialize;

use nexus_config::vm as vm_config;
use nexus_network::client::Client;
use nexus_tools_dev::{
    command::common::{
        prove::{CommonProveArgs, LocalProveArgs, ProveArgs},
        public_params::SetupArgs,
    },
    utils::{cargo, path_to_artifact},
};

use crate::{
    command::{public_params::setup_params, DEFAULT_K, DEFAULT_NOVA_IMPL},
    LOG_TARGET,
};

pub fn handle_command(args: ProveArgs) -> anyhow::Result<()> {
    let ProveArgs {
        common_args: CommonProveArgs { release, bin },
        network,
        url,
        local_args,
    } = args;

    let path = path_to_artifact(bin, release)?;

    if !release {
        tracing::warn!(
            target: LOG_TARGET,
            "proving debug build, use `-r` for release",
        )
    }

    if network {
        let url = url.context("url must be specified")?;
        request_prove(&path, &url)
    } else {
        // build artifact if needed
        if release {
            cargo(None, ["build", "--release"])?;
        } else {
            cargo(None, ["build"])?;
        }

        let LocalProveArgs { k, pp_file, nova_impl } = local_args;
        let k = k.unwrap_or(DEFAULT_K);
        let nova_impl = nova_impl.unwrap_or(DEFAULT_NOVA_IMPL);
        local_prove(&path, k, nova_impl, pp_file)
    }
}

fn request_prove(path: &Path, url: &str) -> anyhow::Result<()> {
    // TODO: network errors cannot be converted to anyhow.

    let client = Client::new(url).map_err(|err| anyhow::anyhow!("url is invalid: {err}"))?;
    let proof = client
        .submit_proof("account".to_string(), path)
        .map_err(|err| anyhow::anyhow!("failed to send request: {err}"))?;

    tracing::info!(
        target: LOG_TARGET,
        hash = %proof.hash,
        "Prove request submitted",
    );

    Ok(())
}

fn local_prove(
    path: &Path,
    k: usize,
    nova_impl: vm_config::NovaImpl,
    pp_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    // setup if necessary
    let pp_file = if let Some(path) = pp_file {
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
        setup_params(SetupArgs {
            k: Some(k),
            nova_impl: Some(nova_impl),
            path: None,
            force: false,
        })?
    };
    let path_str = pp_file.to_str().context("path is not valid utf8")?;

    let opts = nexus_riscv::VMOpts {
        k,
        nop: None,
        loopk: None,
        machine: None,
        file: Some(path.into()),
    };
    let trace = nexus_prover::run(&opts, true)?;

    if nova_impl == vm_config::NovaImpl::Parallel {
        let state = nexus_prover::pp::gen_or_load(false, DEFAULT_K, path_str)?;
        let root = nexus_prover::prove_par(state, trace)?;

        let mut buf = Vec::new();
        root.serialize_compressed(&mut buf)?;

        let current_dir = std::env::current_dir()?;
        let path = current_dir.join("nexus-proof.json");
        tracing::info!(
            target: LOG_TARGET,
            path = %path.to_string_lossy(),
            "Storing the proof",
        );
        let proof = nexus_network::api::Proof { proof: Some(buf), ..Default::default() };

        let serialized = serde_json::to_vec(&proof)?;
        std::fs::write(path, serialized)?;
    } else {
        let state = nexus_prover::pp::gen_or_load(false, DEFAULT_K, path_str)?;
        nexus_prover::prove_seq(&state, trace)?;

        tracing::warn!(
            target: LOG_TARGET,
            "Storing proofs on disk requires parallel mode",
        );
    }

    Ok(())
}
