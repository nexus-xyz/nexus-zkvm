use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;
use nexus_api::config::{
    vm::{NovaImpl, ProverImpl},
    Config, NetworkConfig, VmConfig,
};

use crate::{
    command::{
        common::{
            prove::{CommonProveArgs, LocalProveArgs, ProveArgs},
            public_params::SetupArgs,
        },
        dev::{common_impl::public_params::setup_params_from_env, compile_env_configs},
    },
    utils::{cargo, path_to_artifact},
    LOG_TARGET,
};

pub fn handle_command(args: ProveArgs) -> anyhow::Result<()> {
    let ProveArgs {
        common_args: CommonProveArgs { profile, bin },
        network,
        url,
        local_args,
    } = args;

    // make sure configs are compiled
    compile_env_configs(false)?;
    let vm_config = VmConfig::from_env()?;

    let path = path_to_artifact(bin, &profile)?;

    if &profile == "dev" {
        tracing::warn!(
            target: LOG_TARGET,
            "proving debug build",
        )
    }

    if network {
        let url = if let Some(url) = url {
            url
        } else {
            let network_config = NetworkConfig::from_env()?;
            network_config.client.to_string()
        };
        request_prove(&path, &url)
    } else {
        // build artifact if needed
        cargo(None, ["build", "--profile", &profile])?;

        let LocalProveArgs { k, pp_file, prover_impl, srs_file } = local_args;
        let k = k.unwrap_or(vm_config.k);
        let prover_impl = prover_impl.unwrap_or(vm_config.prover);
        local_prove(&path, k, prover_impl, pp_file, srs_file)
    }
}

fn request_prove(path: &Path, url: &str) -> anyhow::Result<()> {
    // submit <path>
    let path = path.to_str().context("path is not valid utf8")?;
    let mut client_opts = vec![format!("--url={url}")];
    client_opts.extend([String::from("submit"), path.into()]);

    let mut cargo_opts: Vec<String> = ["run", "-p", "nexus-network", "--bin", "client", "--"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut client_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}

fn local_prove(
    path: &Path,
    k: usize,
    prover: ProverImpl,
    pp_file: Option<PathBuf>,
    srs_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let nova_impl = match prover {
        ProverImpl::Jolt => unimplemented!(),
        ProverImpl::Nova(nova_impl) => nova_impl,
    };
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
        setup_params_from_env(SetupArgs {
            k: Some(k),
            nova_impl: Some(nova_impl),
            path: None,
            force: false,
            srs_file,
        })?
    };

    // <path> -k=<k> [-m] [-p=<pp_file>] [-P] [--gen]
    let mut prover_opts = vec![path.as_os_str().to_os_string(), format!("-k={k}").into()];
    if nova_impl == NovaImpl::Parallel {
        prover_opts.push("-P".into());
    }

    let path = pp_file.to_str().context("path is not valid utf8")?;
    prover_opts.push(format!("-p={path}").into());

    let mut cargo_opts: Vec<OsString> = ["run", "--release", "-p", "nexus-prover", "prove"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut prover_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
