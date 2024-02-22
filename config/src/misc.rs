use std::path::PathBuf;

use super::Config;

#[derive(serde_wrapper::Deserialize)]
pub struct MiscConfig {
    pub cache: PathBuf,
}

// NOTE: there's no base value for cache path -- cli reuse workspace target directory for simplicity.
//
// Subject to change.
impl Config for MiscConfig {
    const PREFIX: &'static str = "";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config() {
        std::env::set_var("NEXUS_CACHE", "/dev/null");

        <MiscConfig as Config>::from_env().unwrap();
    }
}
