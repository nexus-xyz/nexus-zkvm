use std::path::{Path, PathBuf};

use anyhow::Context;
use nexus_config::{vm as vm_config, Config};

use crate::{
    command::{
        common::public_params::{
            format_params_file, PublicParamsAction, PublicParamsArgs, SetupArgs,
        },
        dev::{cache_path, compile_env_configs},
    },
    utils::cargo,
    LOG_TARGET,
};

pub(crate) fn handle_command(args: PublicParamsArgs) -> anyhow::Result<()> {
    let action = args
        .command
        .unwrap_or_else(|| PublicParamsAction::Setup(SetupArgs::default()));
    match action {
        PublicParamsAction::Setup(setup_args) => {
            let _ = setup_params_from_env(setup_args)?;
        }
    }
    Ok(())
}

pub(crate) fn setup_params_from_env(args: SetupArgs) -> anyhow::Result<PathBuf> {
    // make sure configs are compiled
    compile_env_configs(false)?;
    let vm_config = vm_config::VmConfig::from_env()?;

    let force = args.force;
    let k = args.k.unwrap_or(vm_config.k);
    let nova_impl = args.nova_impl.unwrap_or(vm_config.nova_impl);
    let srs_file = args.srs_file.as_deref();

    let path = match args.path {
        Some(path) => path,
        None => {
            let pp_file_name = format_params_file(nova_impl, k);
            cache_path()?.join(pp_file_name)
        }
    };

    if !force && path.try_exists()? {
        tracing::info!(
            target: LOG_TARGET,
            "path {} already exists, use `setup --force` to overwrite",
            path.display(),
        );
        return Ok(path);
    }

    setup_params_to_file(&path, nova_impl, k, srs_file)?;
    Ok(path)
}

fn setup_params_to_file(
    path: &Path,
    nova_impl: vm_config::NovaImpl,
    k: usize,
    _srs_file: Option<&Path>,
) -> anyhow::Result<()> {
    // <path> -k=<k> [-p=<pp_file>] [--par]
    let mut prover_opts = vec![
        format!("-p={}", path.to_str().context("path is not valid utf8")?),
        format!("-k={k}"),
    ];
    if let vm_config::NovaImpl::Parallel = nova_impl {
        prover_opts.push("-P".into());
    }
    // TODO: handle case of NovaImpl::ParallelCompressible

    let mut cargo_opts: Vec<String> = ["run", "--release", "-p", "nexus-prover", "gen"]
        .into_iter()
        .map(From::from)
        .collect();
    cargo_opts.append(&mut prover_opts);

    // run from workspace
    cargo(cargo_manifest_dir_path!().into(), cargo_opts)
}
