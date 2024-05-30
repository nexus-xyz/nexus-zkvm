use serde::de::DeserializeOwned;

pub mod error;

pub mod misc;
pub mod network;
pub mod vm;

pub use self::{error::Error, misc::MiscConfig, network::NetworkConfig, vm::VmConfig};

pub trait Config: DeserializeOwned {
    const PREFIX: &'static str;

    fn from_env() -> Result<Self, Error> {
        let prefix = if Self::PREFIX.is_empty() {
            constants::CONFIG_ENV_PREFIX.to_owned()
        } else {
            [constants::CONFIG_ENV_PREFIX, Self::PREFIX].join(constants::CONFIG_SEPARATOR)
        };

        Ok(config::Config::builder()
            .add_source(
                config::Environment::with_prefix(&prefix).separator(constants::CONFIG_SEPARATOR),
            )
            .build()?
            .try_deserialize()?)
    }
}

#[doc(hidden)]
pub mod constants {
    /// All environment variables are prefixed to avoid collisions.
    pub const CONFIG_ENV_PREFIX: &str = "NEXUS";
    /// Separator for nested configs and the prefix.
    ///
    /// Note that to avoid ambiguity in path resolution (see https://github.com/SergioBenitez/Figment/issues/12) this
    /// crate uses a wrapper to derive [`serde::Deserialize`]. See [`serde_wrapper`] doc-comments for details.
    pub const CONFIG_SEPARATOR: &str = "_";
    /// File for storing and reading environment variables.
    pub const CONFIG_FILE_NAME: &str = ".config.env";
    /// Full path to [`CONFIG_FILE_NAME`].
    pub const CONFIG_ENV_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.config.env");
}
