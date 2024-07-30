pub use core::fmt::Write;

#[cfg(target_arch = "riscv32", feature = "jolt-io")]
mod riscv32 {
    extern crate alloc;
    use serde::{de::DeserializeOwned, Serialize};

    /// Read an object off the private input tape
    ///
    /// exhausts the private input tape, so can only be used once
    pub fn read_private_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
        panic!("private input is not available when not proving with Jolt")
    }

    /// Read a byte from the private input tape
    pub fn read_from_private_input() -> Option<u8> {
        panic!("private input is not available when not proving with Jolt")
    }

    /// Read an object from the public input
    ///
    /// exhausts the public input, so can only be used once
    #[nexus_rt_macros::io::read_segment(nexus_rt_macros::io::segments::PublicInput)]
    mod public_input {
        pub fn read_public_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
            let mut ret;
            unsafe {
                ret = __inner::fetch_at_offset(true);
            }

            match ret {
                (true, slice) => postcard::take_from_bytes::<T>(slice).map(|(v, _)| v),
                (false, slice) => Err(postcard::Error::DeserializeUnexpectedEnd),
            }
        }

        /// Read a byte from the public input
        pub fn read_from_public_input() -> Option<u8> {
            let mut ret;

            unsafe {
                ret = __inner::fetch_at_offset(false);
            }

            match ret {
                (true, slice) => Some(slice[0]),
                (false, _) => None,
            }
        }
    }
    pub use public_input::{read_public_input, read_from_public_input};

    /// Write an object to the output
    #[nexus_rt_macros::io::write_segment(nexus_rt_macros::io::segments::PublicOutput)]
    pub fn write_output<T: Serialize + ?Sized>(val: &T) {
        let ser: alloc::vec::Vec<u8> = postcard::to_allocvec(&val).unwrap();
        let mut _out: u32;

        write_to_output(ser.as_slice())
    }

    /// Write a slice to the output tape
    #[nexus_rt_macros::io::write_segment(nexus_rt_macros::io::segments::PublicOutput)]
    pub fn write_to_output(b: &[u8]) {
        let mut _out: u32;
        ecall!(3, b.as_ptr(), b.len(), _out);
    }

    /// An empty type representing the VM terminal
    pub struct NexusLog;

    #[nexus_rt_macros::io::write_segment(nexus_rt_macros::io::segments::PublicLogging)]
    impl core::fmt::Write for NexusLog {
        fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
            write_log(s);
            Ok(())
        }
    }
}

#[cfg(target_arch = "riscv32", feature = "jolt-io")]
pub use jolt::*;

/// Prints to the VM terminal
#[cfg(target_arch = "riscv32", feature = "jolt-io")]
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
#[cfg(target_arch = "riscv32", feature = "jolt-io")]
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
