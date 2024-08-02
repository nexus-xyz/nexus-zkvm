#![allow(clippy::needless_doctest_main)]
#![doc = include_str!("../README.md")]

/// Interface into proving with [HyperNova](https://eprint.iacr.org/2023/573).
pub mod hypernova;
/// Experimental interface into proving with [Jolt](https://jolt.a16zcrypto.com/).
pub mod jolt;
/// Interface into proving with [Nova](https://eprint.iacr.org/2021/370).
pub mod nova;

mod traits;
pub use traits::*;

/// Access the outputs of zkVM executions.
pub mod views;

/// Configure the dynamic compilation of guest programs.
pub mod compile;

/// Contains error types for SDK-specific interfaces.
pub mod error;

/// Development macros for for zkVM host functions.
pub use nexus_macro;
