use serde::de::DeserializeOwned;

mod error;

pub mod misc;
pub mod network;
pub mod vm;

pub use self::{error::Error, misc::MiscConfig, network::NetworkConfig, vm::VmConfig};

pub trait Config: DeserializeOwned {
    const PREFIX: &'static str;

    fn from_env() -> Result<Self, Error> {
        let prefix =
            &[constants::CONFIG_ENV_PREFIX, Self::PREFIX].join(constants::CONFIG_SEPARATOR);

        let _result = dotenvy::from_path(constants::CONFIG_ENV_PATH);
        // don't bail in tests to keep them isolated from env files.
        #[cfg(not(test))]
        _result?;

        Ok(config::Config::builder()
            .add_source(
                config::Environment::with_prefix(prefix).separator(constants::CONFIG_SEPARATOR),
            )
            .build()?
            .try_deserialize()?)
    }
}

#[doc(hidden)]
pub mod constants {
    pub const CONFIG_SEPARATOR: &str = "__";
    pub const CONFIG_ENV_PREFIX: &str = "NEXUS";
    pub const CONFIG_FILE_NAME: &str = ".config.env";
    pub const CONFIG_ENV_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.config.env");
}
