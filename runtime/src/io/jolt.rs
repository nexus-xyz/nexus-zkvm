#[cfg(all(target_arch = "riscv32", feature = "jolt-io"))]
mod jolt {
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

    #[nexus_rt_macros::read_segment(PublicInput)]
    mod public_input {
        use super::*;

        /// Read an object from the public input
        ///
        /// exhausts the public input, so can only be used once
        pub fn read_public_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
            let ret;
            unsafe {
                ret = __inner::fetch_at_offset(true);
            }

            match ret {
                Some(bytes) => postcard::take_from_bytes::<T>(bytes.as_slice()).map(|(v, _)| v),
                None => Err(postcard::Error::DeserializeUnexpectedEnd),
            }
        }

        /// Read a byte from the public input
        pub fn read_from_public_input() -> Option<u8> {
            let ret;
            unsafe {
                ret = __inner::fetch_at_offset(false);
            }

            match ret {
                Some(bytes) => Some(bytes[0]),
                None => None,
            }
        }
    }
    pub use public_input::{read_from_public_input, read_public_input};

    #[nexus_rt_macros::write_segment(PublicOutput)]
    mod public_output {
        use super::*;

        /// Write an object to the output
        pub fn write_output<T: Serialize + ?Sized>(val: &T) {
            let ser: alloc::vec::Vec<u8> = postcard::to_allocvec(&val).unwrap();

            write_to_output(ser.as_slice())
        }

        /// Write a slice to the output tape
        pub fn write_to_output(b: &[u8]) {
            let succ;
            unsafe {
                succ = __inner::set_at_offset(b);
            }

            if !succ {
                panic!("Output memory segment is too small");
            }
        }
    }
    pub use public_output::{write_output, write_to_output};

    #[nexus_rt_macros::write_segment(PublicLogging)]
    mod logging {
        /// Write a string to the output memory segment (if large enough).
        pub fn write_log(s: &str) {
            let succ;
            unsafe {
                succ = __inner::set_at_offset(
                    &[
                        s.as_bytes(),
                        &[0x00], // add null-termination
                    ]
                    .concat(),
                );
            }

            if !succ {
                panic!("Logging memory segment is too small");
            }
        }

        /// An empty type representing the logging memory segment
        pub struct NexusLog;

        impl core::fmt::Write for NexusLog {
            fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
                write_log(s);
                Ok(())
            }
        }

        /// Write to the logging memory segment
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
    }
    pub use logging::{write_log, NexusLog};
}

#[cfg(all(target_arch = "riscv32", feature = "jolt-io"))]
pub use jolt::*;
