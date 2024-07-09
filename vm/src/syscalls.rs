//! Implementation of system calls

use std::collections::VecDeque;
use std::io::Write;

use crate::{
    error::{NexusVMError::UnknownECall, Result},
    memory::Memory,
    rv32::LOP,
};

/// Holds information related to syscall implementation.
#[derive(Default)]
pub struct Syscalls {
    to_stdout: bool,
    log_buffer: Vec<u8>,
    input: VecDeque<u8>,
    output: Vec<u8>,
}

impl Syscalls {
    pub fn enable_stdout(&mut self) {
        self.to_stdout = true;
    }

    pub fn disable_stdout(&mut self) {
        self.to_stdout = false;
    }

    pub fn set_input(&mut self, slice: &[u8]) {
        self.input = slice.to_owned().into();
    }

    pub fn get_output(&mut self) -> Vec<u8> {
        self.output.clone()
    }

    pub fn get_log_buffer(&mut self) -> Vec<u8> {
        self.log_buffer.clone()
    }

    pub fn syscall(&mut self, pc: u32, regs: [u32; 32], memory: &impl Memory) -> Result<u32> {
        let num = regs[18]; // s2 = x18  syscall number
        let inp1 = regs[11]; // a1 = x11
        let inp2 = regs[12]; // a2 = x12

        let mut ret = 0x0;

        if num == 1 {
            // write_log
            for addr in inp1..inp1 + inp2 {
                let b = memory.load(LOP::LBU, addr)?.0;
                self.log_buffer.push(b as u8);
            }

            if self.to_stdout {
                let mut stdout = std::io::stdout();
                stdout.write_all(self.log_buffer.as_slice())?;

                let _ = stdout.flush();
                self.log_buffer.clear();
            }
        } else if num == 2 {
            // read_from_private_input
            match self.input.pop_front() {
                Some(b) => ret = b as u32,
                None => ret = u32::MAX, // out of range of possible u8 inputs
            }
        } else if num == 3 {
            // write_to_output
            for addr in inp1..inp1 + inp2 {
                let b = memory.load(LOP::LBU, addr)?.0;
                self.output.push(b as u8);
            }
        } else {
            return Err(UnknownECall(pc, num));
        }

        Ok(ret)
    }
}
