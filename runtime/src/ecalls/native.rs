#[cfg(not(target_arch = "riscv32"))]
pub use std::{print, println};

/// Read an object off the private input tape
#[cfg(not(target_arch = "riscv32"))]
pub fn read_private_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
    panic!("private input is not available outside of NexusVM")
}

/// Read a byte from the private input tape
#[cfg(not(target_arch = "riscv32"))]
pub fn read_from_private_input() -> Option<u8> {
    panic!("private input is not available outside of NexusVM")
}

/// Write an object to the output tape
#[cfg(not(target_arch = "riscv32"))]
pub fn write_output<T: serde::Serialize + ?Sized>(_: &T) {
    panic!("output is not available outside of NexusVM")
}

/// Write a slice to the output tape
#[cfg(not(target_arch = "riscv32"))]
pub fn write_to_output(_: &[u8]) {
    panic!("output is not available outside of NexusVM")
}
