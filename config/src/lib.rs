//! Environment-based workspace configuration primitives.
//!
//! Allows reading env variables into Rust structures that can be deserialized with [`serde`].
//! Implementing [`Config`] trait only requires specifying a prefix for the config:
//! ```
//! #[derive(serde_wrapper::Deserialize)]
//! struct SimpleConfig {
//!     pub integer_value: u16,
//!     pub url: url::Url,
//! }
//!
//! impl nexus_config::Config for SimpleConfig {
//!     const PREFIX: &'static str = "SIMPLE";
//! }
//! ```
//!
//! Reading a config from the environment with `<SimpleConfig as Config>::from_env()` requires
//! both `NEXUS_SIMPLE_INTEGERVALUE` and `NEXUS_SIMPLE_URL` being defined. Note that the struct
//! name doesn't matter, and underscores are removed from field names.
//!
//! By convention, `Default::default()` should return configurations for local usage, for example
//! - prover configuration with reduced RAM requirement
//! - localhost bind address

use serde::de::DeserializeOwned;

mod error;

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
}
