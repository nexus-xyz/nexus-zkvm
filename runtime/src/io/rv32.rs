pub use core::fmt::Write;

#[cfg(target_arch = "riscv32", not(feature = "jolt-io"))]
mod riscv32 {
    extern crate alloc;
    use serde::{de::DeserializeOwned, Serialize};

    // To simplify calling out to the environment, we keep the
    // argument registers intact, and place the function number
    // in s2 (rust will not allow us to use s0 or s1).
    macro_rules! ecall {
        ($n:literal,$inp1:expr,$inp2:expr,$out:expr) => {
            unsafe {
                core::arch::asm!("ecall", in("s2") $n, in("a1") $inp1, in("a2") $inp2, out("a0") $out)
            }
        }
    }

    /// Write a string to the output console (if any).
    pub fn write_log(s: &str) {
        let mut _out: u32;
        ecall!(1, s.as_ptr(), s.len(), _out);
    }

    /// Read an object off the private input tape
    ///
    /// exhausts the private input tape, so can only be used once
    pub fn read_private_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
        let bytes: alloc::vec::Vec<u8> = core::iter::from_fn(read_from_private_input).collect();
        postcard::from_bytes::<T>(bytes.as_slice())
    }

    /// Read a byte from the private input tape
    pub fn read_from_private_input() -> Option<u8> {
        let inp: u32 = 0;
        let mut out: u32;
        ecall!(2, inp, inp, out);

        if out == u32::MAX {
            None
        } else {
            Some(out.to_le_bytes()[0])
        } // u32::MAX is used a sentinel value that there is nothing (left) on the input tape
    }

    /// Read an object off the public input tape
    pub fn read_public_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
        panic!("public input is not available when not proving with Jolt")
    }

    /// Read a byte from the public input tape
    pub fn read_from_public_input() -> Option<u8> {
        panic!("public input is not available when not proving with Jolt")
    }

    /// Write an object to the output tape
    pub fn write_output<T: Serialize + ?Sized>(val: &T) {
        let ser: alloc::vec::Vec<u8> = postcard::to_allocvec(&val).unwrap();
        let mut _out: u32;

        write_to_output(ser.as_slice())
    }

    /// Write a slice to the output tape
    pub fn write_to_output(b: &[u8]) {
        let mut _out: u32;
        ecall!(3, b.as_ptr(), b.len(), _out);
    }

    /// Bench cycles with input is function name
    pub fn cycle_count_ecall(s: &str) {
        let mut _out: u32;
        ecall!(5, s.as_ptr(), s.len(), _out);
    }

    /// An empty type representing the VM terminal
    pub struct NexusLog;

    impl core::fmt::Write for NexusLog {
        fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
            write_log(s);
            Ok(())
        }
    }
}

#[cfg(target_arch = "riscv32", not(feature = "jolt-io"))]
pub use riscv32::*;

/// Prints to the VM terminal
#[cfg(target_arch = "riscv32", not(feature = "jolt-io"))]
#[macro_export]
macro_rules! print {
    ($($as:tt)*) => {
        <nexus_rt::NexusLog as core::fmt::Write>::write_fmt(
            &mut nexus_rt::NexusLog,
            core::format_args!($($as)*),
        )
        .unwrap()
    }
}

/// Prints to the VM terminal, with a newline
#[cfg(target_arch = "riscv32", not(feature = "jolt-io"))]
#[macro_export]
macro_rules! println {
    () => {
        nexus_rt::print!("\n")
    };
    ($($as:tt)*) => {
        <nexus_rt::NexusLog as core::fmt::Write>::write_fmt(
            &mut nexus_rt::NexusLog,
            core::format_args!("{}\n", core::format_args!($($as)*)),
        )
        .unwrap()
    };
}
