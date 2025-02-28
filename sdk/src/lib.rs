#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]

/// Common exit codes produced by the Nexus runtime (`nexus-rt`).
#[derive(Debug)]
pub enum KnownExitCodes {
    ExitSuccess = 0,
    ExitPanic = 1,
}

/// Interface into proving with Stwo, a highly-efficient Circle STARK.
pub mod stwo;

/// Legacy prover integrations.
#[cfg(feature = "legacy")]
pub mod legacy;

mod traits;
pub use traits::*;

/// Configure the dynamic compilation of guest programs.
pub mod compile;

/// Error types for SDK-specific interfaces.
pub mod error;

/// Development macros for zkVM hosts.
pub use nexus_sdk_macros;
