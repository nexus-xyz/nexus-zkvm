//! Extension config is derived from extensions list and hints the base component if it should enable
//! optional constraints and trace generation.

use std::collections::HashSet;

use super::ExtensionComponent;

#[derive(Default, Debug, Clone)]
pub struct ExtensionsConfig(HashSet<ExtensionComponent>);

impl From<&[ExtensionComponent]> for ExtensionsConfig {
    fn from(extensions: &[ExtensionComponent]) -> Self {
        let mut set = HashSet::new();

        for ext in extensions.iter().cloned() {
            if !set.insert(ext) {
                panic!("prover extensions must be unique")
            }
        }
        Self(set)
    }
}

impl ExtensionsConfig {
    pub fn is_keccak_enabled(&self) -> bool {
        let keccak_extensions = ExtensionComponent::keccak_extensions();
        let (memory_checker, rem) = keccak_extensions
            .split_first()
            .expect("keccak extensions are not empty");

        let result = self.0.contains(memory_checker);
        assert!(
            rem.iter().all(|ext| self.0.contains(ext) == result),
            "keccak components cannot be enabled partially"
        );

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config() {
        let config = ExtensionsConfig::from(ExtensionComponent::keccak_extensions());
        assert!(config.is_keccak_enabled());
    }

    #[test]
    #[should_panic = "keccak components cannot be enabled partially"]
    fn invalid_config_panic() {
        let config = ExtensionsConfig::from(&ExtensionComponent::keccak_extensions()[1..]);
        let _ = config.is_keccak_enabled();
    }
}
