pub use core::fmt::Write;

// To simplify calling out to the environment, we keep the
// argument registers intact, and place the function number
// in s2 (rust will not allow us to use s0 or s1).
//
// todo: with some fancy variadics these could probably be combined

macro_rules! ecall_in {
    ($n:literal,$a0:expr) => {
        unsafe {
            core::arch::asm!("ecall", in("s2") $n, out("a0") $a0)
        }
    }
}

macro_rules! ecall_out {
    ($n:literal,$a0:expr,$a1:expr) => {
        unsafe {
            core::arch::asm!("ecall", in("s2") $n, in("a0") $a0, in("a1") $a1)
        }
    }
}

/// Write a string to the output console (if any).
pub fn write_log(s: &str) {
    ecall_out!(1, s.as_ptr(), s.len());
}

/// Read a byte from the private input tape
pub fn read_from_private_input() -> Option<u8> {
    let mut val: u32;
    ecall_in!(2, val);

    if val == u32::MAX { None } else { Some(val.to_le_bytes()[0]) } // u32::MAX is used a sentinel value that there is nothing (left) on the input tape
}

/// An empty type representing the VM terminal
pub struct NexusLog;

impl Write for NexusLog {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        write_log(s);
        Ok(())
    }
}

/// Prints to the VM terminal
#[macro_export]
macro_rules! print {
    ($($as:tt)*) => {
        core::write!(&mut nexus_rt::NexusLog, $($as)*).unwrap();
    }
}

/// Prints to the VM terminal, with a newline
#[macro_export]
macro_rules! println {
    ($($as:tt)*) => {
        core::writeln!(&mut nexus_rt::NexusLog, $($as)*).unwrap();
    }
}
