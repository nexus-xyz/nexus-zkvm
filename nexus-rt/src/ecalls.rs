pub use core::{fmt::Write};

// To simplify calling out to the environment, we keep the
// argument registers intact, and place the function number
// in s2 (rust will not allow us to use s0 or s1).

macro_rules! ecall {
    ($n:literal,$a0:expr,$a1:expr) => {
        unsafe {
            core::arch::asm!("ecall", in("s2") $n, in("a0") $a0, in("a1") $a1)
        }
    }
}

/// Write a string to the output console (if any).
pub fn write_log(s: &str) {
    ecall!(1, s.as_ptr(), s.len());
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
