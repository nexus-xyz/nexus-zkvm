mod rv32;
mod jolt;
mod native;

#[cfg(target_arch = "riscv32", not(feature = "jolt-io"))]
pub use rv32::*;

#[cfg(target_arch = "riscv32", feature = "jolt-io")]
pub use jolt::*;

#[cfg(not(target_arch = "riscv32"))]
pub use native::*;
