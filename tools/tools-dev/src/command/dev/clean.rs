use std::{fs, io};

use nexus_api::config::constants::{CONFIG_ENV_PATH, CONFIG_FILE_NAME};

use crate::{command::dev::cache_path, LOG_TARGET};

pub(crate) fn handle_command() -> anyhow::Result<()> {
    let cache_path = cache_path()?;

    tracing::info!(
        target: LOG_TARGET,
        "removing {} and the cache at {}",
        CONFIG_FILE_NAME,
        cache_path.display(),
    );

    filter_error(fs::remove_file(CONFIG_ENV_PATH))?;
    filter_error(fs::remove_dir_all(cache_path))?;

    Ok(())
}

fn filter_error(result: io::Result<()>) -> anyhow::Result<()> {
    if let Err(err) = &result {
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
    }
    result.map_err(Into::into)
}
