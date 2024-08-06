//! Implementation of system calls

use std::collections::VecDeque;
use std::io::Write;

use crate::{
    error::{NexusVMError::UnknownECall, Result},
    memory::Memory,
};

/// Holds information related to syscall implementation.
#[derive(Default)]
pub struct Syscalls {
    to_stdout: bool,
    log_buffer: Vec<Vec<u8>>,
    input: VecDeque<u8>,
    output: Vec<u8>,
    label: Vec<Vec<u8>>,
}

pub enum SyscallCode {
    WriteLog = 1,
    ReadFromPrivateInput = 2,
    WriteToOutput = 3,
    ProfileCycles = 5,
}

impl SyscallCode {
    fn try_from(pc: u32, syscode: u32) -> Result<Self> {
        match syscode {
            1 => Ok(SyscallCode::WriteLog),
            2 => Ok(SyscallCode::ReadFromPrivateInput),
            3 => Ok(SyscallCode::WriteToOutput),
            5 => Ok(SyscallCode::ProfileCycles),
            _ => Err(UnknownECall(pc, syscode)),
        }
    }
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

    pub fn get_log_buffer(&mut self) -> Vec<Vec<u8>> {
        self.log_buffer.clone()
    }

    pub fn get_label(&mut self) -> Option<Vec<u8>> {
        self.label.pop()
    }
    /// Read `len` bytes from memory starting at `source` to log.
    /// If `to_stdout` is true, writes the log to standard output; otherwise, stores it in `log_buffer`.
    ///
    /// # Arguments
    ///
    /// * `source` - Starting address in memory to read the log from.
    /// * `len` - Number of bytes to read from memory.
    /// * `memory` - A reference to the memory implementation.
    ///
    /// # Returns
    ///
    /// A `Result<u32>` indicating success or any encountered errors.
    fn writelog(&mut self, source: u32, len: u32, memory: &impl Memory) -> Result<u32> {
        let nxt = memory.load_n(source, len)?;

        if self.to_stdout {
            let mut stdout = std::io::stdout();
            stdout.write_all(nxt.as_slice())?;

            let _ = stdout.flush();
        } else {
            self.log_buffer.push(nxt.clone());
        }
        Ok(0)
    }

    /// Reads a value from the private input buffer.
    /// If the buffer is empty, returns `u32::MAX`.
    ///
    /// # Returns
    ///
    /// A `Result<u32>` containing the read value or indicating success or any encountered error.
    fn read_from_private_input(&mut self) -> Result<u32> {
        Ok(self.input.pop_front().map_or(u32::MAX, |b| b as u32))
    }

    /// Writes `len` bytes from memory starting at `source` to the output.
    ///
    /// # Arguments
    ///
    /// * `source` - Starting address in memory to read the output from.
    /// * `len` - Number of bytes to read from memory.
    /// * `memory` - A reference to the memory implementation.
    ///
    /// # Returns
    ///
    /// A `Result<u32>` indicating success or any encountered errors.
    fn write_to_output(&mut self, source: u32, len: u32, memory: &impl Memory) -> Result<u32> {
        self.output.extend(memory.load_n(source, len)?);
        Ok(0)
    }

    /// Profiles cycles by reading `len` bytes starting at `source`
    /// and storing them in the `label` vector.
    ///
    /// # Arguments
    ///
    /// * `source` - Starting address in memory to read the output from.
    /// * `len` - Number of bytes to read from memory.
    /// * `memory` - A reference to the memory implementation.
    ///
    /// # Returns
    ///
    /// A `Result<u32>` containing the profile cycles syscall code or indicating success or any encountered errors.
    fn profile_cycles(&mut self, source: u32, len: u32, memory: &impl Memory) -> Result<u32> {
        // cycles benchmark
        let buf = memory.load_n(source, len)?;
        self.label.push(buf);
        Ok(SyscallCode::ProfileCycles as u32)
    }

    /// Handles the syscall based on the given program counter, registers, and memory.
    ///
    /// # Arguments
    ///
    /// * `pc` - Program counter.
    /// * `regs` - Array of 32 registers.
    /// * `memory` - A reference to the memory implementation.
    ///
    /// # Returns
    ///
    /// A `Result<u32>` indicating success or any encountered errors.
    pub fn syscall(&mut self, pc: u32, regs: [u32; 32], memory: &impl Memory) -> Result<u32> {
        let code = SyscallCode::try_from(pc, regs[18])?; // s2 = x18  syscall number
        let rs1 = regs[11]; // a1 = x11
        let rs2 = regs[12]; // a2 = x12

        match code {
            SyscallCode::WriteLog => self.writelog(rs1, rs2, memory),
            SyscallCode::ReadFromPrivateInput => self.read_from_private_input(),
            SyscallCode::WriteToOutput => self.write_to_output(rs1, rs2, memory),
            SyscallCode::ProfileCycles => self.profile_cycles(rs1, rs2, memory),
        }
    }
}
