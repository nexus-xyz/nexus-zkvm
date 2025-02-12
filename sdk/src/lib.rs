#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]

#[derive(Debug)]
pub enum KnownErrorCodes {
    ExitSuccess = 0,
    ExitPanic = 1,
}

/// Interface into proving with Stwo.
pub mod stwo;

/// Legacy prover integrations.
#[cfg(feature = "legacy")]
pub mod legacy;

/// Interface into proving with [HyperNova](https://eprint.iacr.org/2023/573).
#[cfg(feature = "legacy-hypernova")]
pub use legacy::hypernova;

/// Experimental interface into proving with [Jolt](https://jolt.a16zcrypto.com/).
#[cfg(feature = "legacy-jolt")]
pub use legacy::jolt;

/// Interface into proving with [Nova](https://eprint.iacr.org/2021/370)
#[cfg(feature = "legacy-nova")]
pub use legacy::nova;

mod traits;
pub use traits::*;

/// Configure the dynamic compilation of guest programs.
pub mod compile;

/// Contains error types for SDK-specific interfaces.
pub mod error;

/// Development macros for zkVM hosts.
pub use nexus_sdk_macros;
