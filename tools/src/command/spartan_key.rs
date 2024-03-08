use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use nexus_config::{vm as vm_config, Config};
use nexus_prover::srs::get_min_srs_size;
use nexus_tools_dev::command::common::{
    public_params::{format_params_file, format_srs_file},
    spartan_key::{format_key_file, SetupArgs, SpartanSetupAction, SpartanSetupArgs},
};

use crate::{command::cache_path, LOG_TARGET};

pub fn handle_command(args: SpartanSetupArgs) -> anyhow::Result<()> {
    let action = args
        .command
        .unwrap_or_else(|| SpartanSetupAction::Setup(SetupArgs::default()));
    match action {
        SpartanSetupAction::Setup(setup_args) => {
            let _ = spartan_setup(setup_args)?;
        }
    }
    Ok(())
}

pub(crate) fn spartan_setup(args: SetupArgs) -> anyhow::Result<PathBuf> {
    let vm_config = vm_config::VmConfig::from_env()?;

    let force = args.force;
    let k = args.k.unwrap_or(vm_config.k);
    let nova_impl = vm_config::NovaImpl::ParallelCompressible;
    let pp_file = match args.pp_file {
        None => {
            let pp_file = format_params_file(nova_impl, k);
            let cache_path = cache_path()?;

            cache_path.join(pp_file)
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
    }

    let srs_file = match args.srs_file {
        None => {
            let srs_file_name = format_srs_file(get_min_srs_size(k)?);
            let cache_path = cache_path()?;

            cache_path.join(srs_file_name)
        }
        Some(path) => path,
    };
    if !srs_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            srs_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    }

    let key_path = match args.path {
        Some(path) => path,
        None => {
            let key_file_name = format_key_file(vm_config.k);
            let cache_path = cache_path()?;
            cache_path.join(key_file_name)
        }
    };
    if !force && key_path.try_exists()? {
        tracing::info!(
            target: LOG_TARGET,
            "path {} already exists, use `setup --force` to overwrite",
            key_path.display(),
        );
        return Ok(key_path);
    }
    spartan_setup_to_file(&key_path, &pp_file, &srs_file)?;
    Ok(key_path)
}

fn spartan_setup_to_file(key_path: &Path, pp_path: &Path, srs_path: &Path) -> anyhow::Result<()> {
    let key_path = key_path.to_str().context("path is not valid utf8")?;
    let pp_path_str = pp_path.to_str().context("path is not valid utf8")?;
    let srs_path_str = srs_path.to_str().context("path is not valid utf8")?;
    nexus_prover::key::gen_key_to_file(pp_path_str, srs_path_str, key_path)?;

    Ok(())
}
