use std::path::PathBuf;

use serde::Deserialize;

use super::{Config, Error};

#[derive(Deserialize)]
pub struct MiscConfig {
    pub cache_path: PathBuf,
}

impl Config for MiscConfig {
    const PREFIX: &'static str = "MISC";

    fn from_env() -> Result<Self, Error> {
        // NOTE: non-configurable -- hardcoded to reuse workspace target directory for simplicity.
        //
        // Subject to change.
        let manifest_path: PathBuf = env!("CARGO_MANIFEST_DIR").into();
        let cache_path = manifest_path
            .parent()
            .expect("parent directory not found")
            .join("target/nexus-cache");
        Ok(Self { cache_path })
    }
}
