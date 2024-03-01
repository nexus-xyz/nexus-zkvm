use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::Context;

use nexus_config::{vm as vm_config, Config};
use nexus_tools_dev::command::common::spartan_key::{
    format_key_file, SetupArgs, SpartanSetupAction, SpartanSetupArgs,
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
    if !args.pp_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            args.pp_file.display(),
        );
        Err(io::Error::from(io::ErrorKind::NotFound).into())
    } else if !args.srs_file.try_exists()? {
        tracing::error!(
            target: LOG_TARGET,
            "path {} was not found",
            args.srs_file.display(),
        );
        return Err(io::Error::from(io::ErrorKind::NotFound).into());
    } else {
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
        spartan_setup_to_file(&key_path, &args.pp_file, &args.srs_file)?;
        Ok(key_path)
    }
}

fn spartan_setup_to_file(key_path: &Path, pp_path: &Path, srs_path: &Path) -> anyhow::Result<()> {
    let key_path = key_path.to_str().context("path is not valid utf8")?;
    let pp_path_str = pp_path.to_str().context("path is not valid utf8")?;
    let srs_path_str = srs_path.to_str().context("path is not valid utf8")?;
    nexus_prover::key::gen_key_to_file(pp_path_str, srs_path_str, key_path)?;

    Ok(())
}
