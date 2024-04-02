use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use nexus_config::{vm as vm_config, Config};
use nexus_tools_dev::{
    command::common::{
        prove::{CommonProveArgs, LocalProveArgs, ProveArgs},
        public_params::SetupArgs,
    },
    utils::{cargo, path_to_artifact},
};

use crate::{command::public_params::setup_params, LOG_TARGET};

pub fn handle_command(args: ProveArgs) -> anyhow::Result<()> {
    let ProveArgs {
        common_args: CommonProveArgs { release, profile, bin },
        network,
        url,
        local_args,
    } = args;

    let profile = if release {
        "release".to_string()
    } else {
        profile
    };

    let path = path_to_artifact(bin, &profile)?;
    let vm_config = vm_config::VmConfig::from_env()?;

    if &profile == "dev" {
        tracing::warn!(
            target: LOG_TARGET,
            "proving debug build",
        )
    }

    if network {
        let url = url.context("url must be specified")?;
        request_prove(&path, &url)
    } else {
        // build artifact if needed
        cargo(None, ["build", "--profile", &profile])?;

        let LocalProveArgs { k, pp_file, nova_impl, srs_file } = local_args;
        let k = k.unwrap_or(vm_config.k);
        let nova_impl = nova_impl.unwrap_or(vm_config.nova_impl);
        local_prove(&path, k, nova_impl, pp_file, srs_file)
    }
}

fn request_prove(_path: &Path, _url: &str) -> anyhow::Result<()> {
    // TODO: network errors cannot be converted to anyhow.

    // let client = Client::new(url).map_err(|err| anyhow::anyhow!("url is invalid: {err}"))?;
    // let proof = client
    //     .submit_proof("account".to_string(), path)
    //     .map_err(|err| anyhow::anyhow!("failed to send request: {err}"))?;

    // tracing::info!(
    //     target: LOG_TARGET,
    //     hash = %proof.hash,
    //     "Prove request submitted",
    // );
    tracing::warn!(
        target: LOG_TARGET,
        "Networking commands are disabled",
    );

    Ok(())
}

fn local_prove(
    path: &Path,
    k: usize,
    nova_impl: vm_config::NovaImpl,
    pp_file: Option<PathBuf>,
    srs_file: Option<PathBuf>,
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
            srs_file,
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

    let current_dir = std::env::current_dir()?;
    let proof_path = current_dir.join("nexus-proof");

    match nova_impl {
        vm_config::NovaImpl::Parallel => {
            let state = nexus_prover::pp::gen_or_load(false, k, path_str, None)?;
            let root = nexus_prover::prove_par(state, trace)?;

            nexus_prover::save_proof(root, &proof_path)?;
        }
        vm_config::NovaImpl::ParallelCompressible => {
            let state = nexus_prover::pp::gen_or_load(false, k, path_str, None)?;
            let root = nexus_prover::prove_par_com(state, trace)?;

            nexus_prover::save_proof(root, &proof_path)?;
        }
        vm_config::NovaImpl::Sequential => {
            let state = nexus_prover::pp::gen_or_load(false, k, path_str, None)?;
            let proof = nexus_prover::prove_seq(&state, trace)?;

            nexus_prover::save_proof(proof, &proof_path)?;
        }
    }

    Ok(())
}

// fn save_proof<P: CanonicalSerialize>(proof: P, path: &Path) -> anyhow::Result<()> {
//     tracing::info!(
//         target: LOG_TARGET,
//         path = %path.display(),
//         "Saving the proof",
//     );

//     let mut term = nexus_tui::TerminalHandle::new_enabled();
//     let mut context = term.context("Saving").on_step(|_step| "proof".into());
//     let _guard = context.display_step();

//     let mut buf = Vec::new();

//     proof.serialize_compressed(&mut buf)?;
//     std::fs::write(path, buf)?;

//     Ok(())
// }
