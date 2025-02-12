pub use core::fmt::Write;
extern crate alloc;

#[cfg(target_arch = "riscv32")]
mod riscv32 {
    extern crate alloc;
    use crate::{
        ecall, read_input, write_output, SYS_CYCLE_COUNT, SYS_EXIT, SYS_LOG,
        SYS_READ_PRIVATE_INPUT, WORD_SIZE,
    };
    use serde::{de::DeserializeOwned, Serialize};

    /// Write a string to the output console (if any).
    pub fn write_log(s: &str) -> Option<u32> {
        let fd = 1;
        let buf_ptr = s.as_ptr();
        let buf_len = s.len();
        let out = ecall!(SYS_LOG, fd, ("a1", buf_ptr), ("a2", buf_len));
        if out == u32::MAX {
            None
        } else {
            Some(out)
        }
    }

    /// Exit the program with the given exit code.
    pub fn exit(exit_code: i32) -> ! {
        // Write the exit code to the output.
        let _ = write_output!(0, exit_code);
        // Exit the program.
        let _ = ecall!(SYS_EXIT, exit_code);
        // Ecall will trigger exit syscall, so we will never return.
        unsafe {
            core::hint::unreachable_unchecked();
        }
    }

    /// Read an object off the private input tape
    ///
    /// exhausts the private input tape, so can only be used once
    pub fn read_private_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
        let mut bytes: alloc::vec::Vec<u8> = core::iter::from_fn(read_from_private_input).collect();
        postcard::from_bytes_cobs::<T>(bytes.as_mut_slice())
    }

    /// Read a byte from the private input tape
    fn read_from_private_input() -> Option<u8> {
        let out = ecall!(SYS_READ_PRIVATE_INPUT);

        if out == u32::MAX {
            None
        } else {
            Some(out.to_le_bytes()[0])
        } // u32::MAX is used a sentinel value that there is nothing (left) on the input tape
    }

    /// Read an object from the public input segment.
    pub fn read_public_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
        // The first word stores the length of the input (in bytes).
        // This length does not take into account the first word itself.
        let len = read_input!(0) as usize;
        let padded_len = (len + 3) & !3;
        let mut input = alloc::vec![0u8; padded_len];

        // Read the input into the vector.
        for i in 0..((padded_len) / WORD_SIZE) {
            let word = read_input!((i + 1) * WORD_SIZE);
            input[i * WORD_SIZE..(i + 1) * WORD_SIZE].copy_from_slice(&word.to_le_bytes());
        }

        // Deserialize the input into the target type.
        postcard::from_bytes_cobs::<T>(input.as_mut_slice())
    }

    /// Write an object to the public output segment.
    pub fn write_public_output<T: Serialize + ?Sized>(val: &T) -> Result<(), postcard::Error> {
        // Serialize the value into bytes.
        let mut bytes = postcard::to_allocvec_cobs(&val)?;

        let padded_len = (bytes.len() + 3) & !3;
        assert!(padded_len >= bytes.len());
        bytes.resize(padded_len, 0x00); // cobs ignores 0x00 padding

        // Write bytes in word chunks to output memory.
        bytes.chunks(WORD_SIZE).enumerate().for_each(|(i, chunk)| {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            write_output!((i + 1) * WORD_SIZE, word); // word 0 is reserved for the exit code
        });

        Ok(())
    }

    /// Bench cycles, where input is the function name
    pub fn cycle_count_ecall(s: &str) {
        let buf = s.as_ptr();
        let len = s.len();
        let _ = ecall!(SYS_CYCLE_COUNT, buf, ("a1", len));
    }

    /// An empty type representing the debug VM terminal
    pub struct NexusLog;

    impl core::fmt::Write for NexusLog {
        fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
            write_log(s);
            Ok(())
        }
    }
}

#[cfg(target_arch = "riscv32")]
pub use riscv32::*;

/// Prints to the VM terminal
#[cfg(target_arch = "riscv32")]
#[macro_export]
macro_rules! print {
    ($($as:tt)*) => {
        <nexus_rt::NexusLog as core::fmt::Write>::write_fmt(
            &mut nexus_rt::NexusLog,
            core::format_args!($($as)*),
        ).unwrap()
    }
}

/// Prints to the VM terminal, with a newline
#[cfg(target_arch = "riscv32")]
#[macro_export]
macro_rules! println {
    () => {
        nexus_rt::print!("\n")
    };
    ($($as:tt)*) => {
        <nexus_rt::NexusLog as core::fmt::Write>::write_fmt(
            &mut nexus_rt::NexusLog,
            core::format_args!("{}\n", core::format_args!($($as)*)),
        ).unwrap()
    }
}

#[allow(private_bounds)]
#[cfg(not(target_arch = "riscv32"))]
mod native {
    // a trait required in the bounds of each of these methods, but which is inaccessible for library users
    // causes use of these functions to fail at compilation, but with a more helpful error than 'not found'
    trait RequiresRV32Target {}

    use serde::{de::DeserializeOwned, Serialize};

    pub fn write_log<UNUSABLE: RequiresRV32Target>(_s: &str) {
        unimplemented!()
    }

    pub fn read_private_input<UNUSABLE: RequiresRV32Target, T: DeserializeOwned>(
    ) -> Result<T, postcard::Error> {
        unimplemented!()
    }

    pub fn read_public_input<UNUSABLE: RequiresRV32Target, T: DeserializeOwned>(
    ) -> Result<T, postcard::Error> {
        unimplemented!()
    }

    pub fn write_public_output<UNUSABLE: RequiresRV32Target, T: Serialize + ?Sized>(_val: &T) {
        unimplemented!()
    }
}
#[cfg(not(target_arch = "riscv32"))]
pub use native::*;

#[cfg(not(target_arch = "riscv32"))]
pub use std::{print, println, process::exit};
