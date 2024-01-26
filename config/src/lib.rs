use std::{
    env,
    path::{Path, PathBuf},
};

use serde::de::DeserializeOwned;

#[cfg(any(test, feature = "compile"))]
mod compile;
mod error;

pub mod vm;

pub use vm::VmConfig;
pub use error::Error;

#[cfg(feature = "compile")]
pub use compile::compile_to_env_from_bases;

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const CONFIG_ENV_PREFIX: &str = "NEXUS";

pub trait Config: DeserializeOwned {
    const PREFIX: &'static str;

    fn from_env() -> Result<Self, Error> {
        let prefix = format!("{}_{}", CONFIG_ENV_PREFIX, Self::PREFIX);
        let _result = dotenvy::from_path(config_env_path());

        // don't bail in tests.
        #[cfg(not(test))]
        _result?;

        Ok(config::Config::builder()
            .add_source(config::Environment::with_prefix(&prefix).separator("_"))
            .build()?
            .try_deserialize()?)
    }
}

#[doc(hidden)]
pub fn config_env_path() -> PathBuf {
    Path::new(CARGO_MANIFEST_DIR).join(".config.env")
}
