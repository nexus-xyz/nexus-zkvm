/// Interface into proving with [HyperNova](https://eprint.iacr.org/2023/573).
#[cfg(feature = "legacy-hypernova")]
pub mod hypernova;

/// Experimental interface into proving with [Jolt](https://jolt.a16zcrypto.com/).
#[cfg(feature = "legacy-jolt")]
pub mod jolt;

/// Interface into proving with [Nova](https://eprint.iacr.org/2021/370).
#[cfg(feature = "legacy-nova")]
pub mod nova;

mod traits;
pub use traits::*;

/// Configure the dynamic compilation of guest programs.
pub mod compile;

/// View the output of an execution.
pub mod views;

#[cfg(any(feature = "legacy-nova", feature = "legacy-hypernova"))]
pub(crate) mod ark_serialize_utils;
