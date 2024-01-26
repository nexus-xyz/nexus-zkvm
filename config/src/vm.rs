use serde::Deserialize;

use super::Config;

#[derive(Deserialize)]
pub struct VmConfig {
    pub k: usize,
}

impl Config for VmConfig {
    const PREFIX: &'static str = "VM";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::load_env;

    #[test]
    fn read_config() {
        load_env();
        <VmConfig as Config>::from_env().unwrap();
    }
}
