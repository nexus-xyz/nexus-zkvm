use std::fmt;

use super::Config;

#[derive(serde_wrapper::Deserialize)]
pub struct VmConfig {
    pub k: usize,
    pub nova_impl: NovaImpl,
}

#[derive(Debug, Copy, Clone, PartialEq, serde_wrapper::Deserialize)]
#[cfg_attr(feature = "clap_derive", derive(clap::ValueEnum))]
pub enum NovaImpl {
    #[serde(rename = "seq")]
    #[cfg_attr(feature = "clap_derive", clap(name = "seq"))]
    Sequential,

    #[serde(rename = "par")]
    #[cfg_attr(feature = "clap_derive", clap(name = "par"))]
    Parallel,

    #[serde(rename = "par-com")]
    #[cfg_attr(feature = "clap_derive", clap(name = "par-com"))]
    ParallelCompressible,
}

impl fmt::Display for NovaImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NovaImpl::Sequential => write!(f, "seq"),
            NovaImpl::Parallel => write!(f, "par"),
            NovaImpl::ParallelCompressible => write!(f, "par-com"),
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
        std::env::set_var("NEXUS_VM_K", "1");
        std::env::set_var("NEXUS_VM_NOVAIMPL", "seq");

        <VmConfig as Config>::from_env().unwrap();
    }
}
