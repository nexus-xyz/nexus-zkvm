#![doc = include_str!("../README.md")]

/// Interface into proving with [HyperNova](https://eprint.iacr.org/2023/573).
pub mod hypernova;
/// Interface into proving with [Jolt](https://jolt.a16zcrypto.com/).
pub mod jolt;
/// Interface into proving with [Nova](https://eprint.iacr.org/2021/370).
pub mod nova;

mod traits;
pub use traits::*;

/// Contains options for dynamic compilation of guest programs.
pub mod compile;

/// Contains error types for SDK-specific interfaces.
pub mod error;
