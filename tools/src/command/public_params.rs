use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use nexus_config::{
    vm::{self as vm_config, ProverImpl},
    Config,
};
use nexus_prover::srs::{get_min_srs_size, test_srs::gen_test_srs_to_file};
use nexus_tools_dev::command::common::public_params::{
    format_params_file, format_srs_file, PublicParamsAction, PublicParamsArgs, SRSSetupArgs,
    SetupArgs,
};

use crate::{command::cache_path, LOG_TARGET};

pub fn handle_command(args: PublicParamsArgs) -> anyhow::Result<()> {
    let action = args
        .command
        .unwrap_or_else(|| PublicParamsAction::Setup(SetupArgs::default()));
    match action {
        PublicParamsAction::Setup(setup_args) => {
            let _ = setup_params(setup_args)?;
        }
        PublicParamsAction::SampleTestSRS(srs_setup_args) => {
            let _ = sample_test_srs(srs_setup_args)?;
        }
    }
    Ok(())
}

pub(crate) fn setup_params(args: SetupArgs) -> anyhow::Result<PathBuf> {
    let vm_config = vm_config::VmConfig::from_env()?;

    let force = args.force;
    let k = args.k.unwrap_or(vm_config.k);
    let nova_impl = if let Some(nova_impl) = args.nova_impl {
        nova_impl
    } else {
        match vm_config.prover {
            ProverImpl::Jolt => anyhow::bail!("Jolt doesn't require Nova-setup"),
            ProverImpl::Nova(nova_impl) => nova_impl,
        }
    };

    let srs_file = args.srs_file;

    let path = match args.path {
        Some(path) => path,
        None => {
            let pp_file_name = format_params_file(nova_impl, k);
            let cache_path = cache_path()?;

            cache_path.join(pp_file_name)
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
    srs_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let path = path.to_str().context("path is not valid utf8")?;
    match nova_impl {
        vm_config::NovaImpl::Sequential => nexus_prover::pp::gen_to_file(k, false, path, None)?,
        vm_config::NovaImpl::Parallel => nexus_prover::pp::gen_to_file(k, true, path, None)?,
        vm_config::NovaImpl::ParallelCompressible => {
            let srs_file = match srs_file {
                None => {
                    let srs_file_name = format_srs_file(get_min_srs_size(k)?);
                    let cache_path = cache_path()?;

                    cache_path.join(srs_file_name)
                }
                Some(file) => file,
            };

            if !srs_file.try_exists()? {
                tracing::error!(
                target: LOG_TARGET,
                "path {} was not found",
                srs_file.display(),
                );
                return Err(io::Error::from(io::ErrorKind::NotFound).into());
            }
            let srs_file_str = srs_file.to_str().context("path is not valid utf8")?;
            nexus_prover::pp::gen_to_file(k, true, path, Some(srs_file_str))?
        }
    };
    Ok(())
}

pub fn sample_test_srs(args: SRSSetupArgs) -> anyhow::Result<PathBuf> {
    let num_vars = match args.num_vars {
        None => {
            let vm_config = vm_config::VmConfig::from_env()?;
            let k = args.k.unwrap_or(vm_config.k);
            get_min_srs_size(k)?
        }
        Some(num_vars) => num_vars,
    };
    let force = args.force;
    let path = match args.file {
        Some(file) => file,
        None => {
            let srs_file_name = format_srs_file(num_vars);
            let cache_path = cache_path()?;

            cache_path.join(srs_file_name)
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

    let path_str = path.to_str().context("path is not valid utf8")?;

    gen_test_srs_to_file(num_vars, path_str)?;
    Ok(path)
}
