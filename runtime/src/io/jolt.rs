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

    #[nexus_rt_macros::read_segment(nexus_rt_macros::io::segments::PublicInput)]
    mod public_input {
        /// Read an object from the public input
        ///
        /// exhausts the public input, so can only be used once
        pub fn read_public_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
            let mut ret;
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
            let mut ret;

            unsafe {
                ret = __inner::fetch_at_offset(false);
            }

            match ret {
                Some(bytes) => Some(bytes[0]),
                None => None,
            }
        }
    }
    pub use public_input::{read_public_input, read_from_public_input};

    #[nexus_rt_macros::write_segment(nexus_rt_macros::io::segments::PublicOutput)]
    mod public_output {
        /// Write an object to the output
        pub fn write_output<T: Serialize + ?Sized>(val: &T) {
            let ser: alloc::vec::Vec<u8> = postcard::to_allocvec(&val).unwrap();

            write_to_output(ser.as_slice())
        }

        /// Write a slice to the output tape
        pub fn write_to_output(b: &[u8]) {
            let mut succ;

            unsafe {
                succ = __inner::set_at_offset(b);
            }

            if !succ {
                panic!("Output memory segment is too small");
            }
        }
    }
    pub use public_output::{write_output, write_to_output};

    #[nexus_rt_macros::write_segment(nexus_rt_macros::io::segments::PublicLogging)]
    mod logging {
        /// Prints to the VM terminal
        #[macro_export]
        macro_rules! print {
            ($($as:tt)*) => {
                let mut succ;

                unsafe {
                    succ = __inner::set_at_offset(&[
                        core::format_args!($($as)*).as_bytes(),
                        &[0x00], // add null-termination
                    ].concat());
                }

                if !succ {
                    panic!("Logging memory segment is too small");
                }
            }
        }

        /// Prints to the VM terminal, with a newline
        #[macro_export]
        macro_rules! println {
            () => {
                nexus_rt::print!("\n")
            };
            ($($as:tt)*) => {
                let mut succ;

                unsafe {
                    succ = __inner::set_at_offset(&[
                        core::format_args!("{}\n", core::format_args!($($as)*)).as_bytes(),
                        &[0x00], // add null-termination
                    ].concat());
                }

                if !succ {
                    panic!("Logging memory segment is too small");
                }

            };
        }
    }
    pub use logging::{print, println};
}

#[cfg(target_arch = "riscv32", feature = "jolt-io")]
pub use jolt::*;
