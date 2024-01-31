use std::fmt;

use serde::Deserialize;

use super::Config;

#[derive(Deserialize)]
pub struct VmConfig {
    pub k: usize,
    pub nova_impl: NovaImpl,
}

#[derive(Debug, Copy, Clone, Deserialize)]
#[cfg_attr(feature = "clap_derive", derive(clap::ValueEnum))]
pub enum NovaImpl {
    #[serde(rename = "seq")]
    #[cfg_attr(feature = "clap_derive", clap(name = "seq"))]
    Sequential,

    #[serde(rename = "par")]
    #[cfg_attr(feature = "clap_derive", clap(name = "par"))]
    Parallel,
}

impl fmt::Display for NovaImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NovaImpl::Sequential => write!(f, "seq"),
            NovaImpl::Parallel => write!(f, "par"),
        }
    }
}

impl Config for VmConfig {
    const PREFIX: &'static str = "VM";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_config() {
        std::env::set_var("NEXUS__VM__K", "1");
        std::env::set_var("NEXUS__VM__NOVA_IMPL", "seq");

        <VmConfig as Config>::from_env().unwrap();
    }
}
