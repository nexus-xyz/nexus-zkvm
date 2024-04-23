//! Implementation of system calls

use std::collections::VecDeque;
use std::io::Write;

use crate::{
    error::{NexusVMError::UnknownSyscall, Result},
    instructions::Width,
    memory::Memory,
};

/// Holds information related to syscall implementation.
pub struct Syscalls {
    output_enable: bool,
    input: VecDeque<u8>,
}

impl Default for Syscalls {
    fn default() -> Self {
        Self {
            output_enable: true,
            input: VecDeque::new(),
        }
    }
}

impl Syscalls {
    pub fn enable_output(&mut self) {
        self.output_enable = true;
    }

    pub fn disable_output(&mut self) {
        self.output_enable = false;
    }

    pub fn set_input(&mut self, slice: &[u8]) {
        self.input = slice.to_owned().into();
    }

    pub fn syscall(&mut self, pc: u32, regs: [u32; 32], memory: &impl Memory) -> Result<u32> {
        let num = regs[18]; // s2 = x18  syscall number
        let inp1 = regs[11]; // a1 = x11
        let inp2 = regs[12]; // a2 = x12

        let mut out = 0x0;

        if num == 1 {
            // write_log
            let mut stdout = std::io::stdout();
            for addr in inp1..inp1 + inp2 {
                let b = memory.load(Width::BU, addr)?.0;
                stdout.write_all(&[b as u8])?;
            }
            let _ = stdout.flush();
        } else if num == 2 {
            // read_from_private_input
            match self.input.pop_front() {
                Some(b) => out = b as u32,
                None => out = u32::MAX,
            }
        } else {
            return Err(UnknownSyscall(pc, num));
        }

        Ok(out)
    }
}
