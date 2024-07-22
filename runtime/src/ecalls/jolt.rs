/// Read an object off the private input tape
#[cfg(not(target_arch = "riscv32"))]
pub fn read_private_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
    panic!("private input is not supported by Jolt")
}

/// Read a byte from the private input tape
#[cfg(not(target_arch = "riscv32"))]
pub fn read_from_private_input() -> Option<u8> {
    panic!("private input is not supported by Jolt")
}
