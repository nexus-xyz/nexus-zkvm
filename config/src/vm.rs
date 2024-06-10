use std::fmt;

use serde::de;
use serde_untagged::UntaggedEnumVisitor;

use super::Config;

#[derive(serde_wrapper::Deserialize)]
pub struct VmConfig {
    pub k: usize,
    pub prover: ProverImpl,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProverImpl {
    Jolt,
    Nova(NovaImpl),
}

#[derive(Debug, Copy, Clone, PartialEq, serde_wrapper::Deserialize)]
#[cfg_attr(feature = "clap_derive", derive(clap::ValueEnum))]
pub enum NovaImpl {
    #[serde(rename = "nova-seq")]
    #[cfg_attr(feature = "clap_derive", clap(name = "nova-seq"))]
    Sequential,

    #[serde(rename = "nova-par")]
    #[cfg_attr(feature = "clap_derive", clap(name = "nova-par"))]
    Parallel,

    #[serde(rename = "nova-par-com")]
    #[cfg_attr(feature = "clap_derive", clap(name = "nova-par-com"))]
    ParallelCompressible,
}

// serde(untagged) errors with clap
impl<'de> de::Deserialize<'de> for ProverImpl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        UntaggedEnumVisitor::new()
            .string(|s| {
                Ok(match s {
                    "jolt" => Self::Jolt,
                    "nova-seq" => Self::Nova(NovaImpl::Sequential),
                    "nova-par" => Self::Nova(NovaImpl::Parallel),
                    "nova-par-com" => Self::Nova(NovaImpl::ParallelCompressible),
                    _ => {
                        // the error message starts with "expected ..."
                        return Err(de::Error::invalid_value(
                            de::Unexpected::Str(s),
                            &r#"one of ["jolt", "nova-seq", "nova-par", "nova-par-com"]"#,
                        ));
                    }
                })
            })
            .deserialize(deserializer)
    }
}

impl fmt::Display for ProverImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProverImpl::Jolt => write!(f, "jolt"),
            ProverImpl::Nova(nova_impl) => write!(f, "{nova_impl}"),
        }
    }
}

impl fmt::Display for NovaImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NovaImpl::Sequential => write!(f, "nova-seq"),
            NovaImpl::Parallel => write!(f, "nova-par"),
            NovaImpl::ParallelCompressible => write!(f, "nova-par-com"),
        }
    }
}

// `derive(ValueEnum)` only works for enums with unit variants -- needs manual implementation.
#[cfg(feature = "clap_derive")]
mod clap_derive {
    use super::{NovaImpl, ProverImpl};
    use clap::{builder::PossibleValue, ValueEnum};

    impl ValueEnum for ProverImpl {
        fn value_variants<'a>() -> &'a [Self] {
            &[
                Self::Jolt,
                Self::Nova(NovaImpl::Sequential),
                Self::Nova(NovaImpl::Parallel),
                Self::Nova(NovaImpl::ParallelCompressible),
            ]
        }

        fn to_possible_value(&self) -> Option<PossibleValue> {
            let str = match self {
                ProverImpl::Jolt => "jolt",
                ProverImpl::Nova(NovaImpl::Sequential) => "nova-seq",
                ProverImpl::Nova(NovaImpl::Parallel) => "nova-par",
                ProverImpl::Nova(NovaImpl::ParallelCompressible) => "nova-par-com",
            };
            Some(PossibleValue::new(str))
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
        std::env::set_var("NEXUS_VM_PROVER", "nova-seq");

        <VmConfig as Config>::from_env().unwrap();
    }
}
