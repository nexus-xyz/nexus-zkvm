#[cfg(target_arch = "riscv32")]
mod riscv32;
#[cfg(target_arch = "riscv32")]
pub use riscv32::*;

#[cfg(not(target_arch = "riscv32"))]
pub use tiny_keccak::*;
