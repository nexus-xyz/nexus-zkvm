//! Syscall implementation for the RISC-V emulator.
//!
//! This module provides the infrastructure for handling system calls in the RISC-V emulator.
//! It defines:
//!
//! - `SyscallCode`: An enumeration of supported system call codes, including both standard
//!   RISC-V syscalls and custom zkVM-specific syscalls.
//!
//! - `SyscallInstruction`: A struct representing a syscall instruction, including its code,
//!   arguments, and result.
//!
//! The module implements the following key functionalities:
//!
//! 1. Decoding syscall instructions from CPU state.
//! 2. Executing various syscalls, such as write, exit, and cycle counting.
//! 3. Handling memory interactions for syscalls.
//! 4. Writing back results to CPU registers.
//!
//! This implementation follows a clear separation of concerns, with distinct methods for
//! instruction decoding, execution, memory operations, and CPU state updates. This design
//! allows for easier testing, maintenance, and potential future extensions of the syscall
//! system.
use std::collections::{hash_map, VecDeque};

use nexus_common::cpu::Registers;

use crate::{
    cpu::Cpu,
    emulator::Emulator,
    error::{Result, VMError},
    memory::MemoryProcessor,
    riscv::{BuiltinOpcode, Instruction, Register},
};

pub enum SyscallCode {
    // Syscall code defines opcodes start from 512
    Write = 512,
    Exit = 513,

    // zkVM specific syscall opcodes start from 1024
    ReadFromPrivateInput = 1024,
    CycleCount = 1025,
}

impl SyscallCode {
    fn try_from(value: u32, pc: u32) -> Result<Self> {
        let code = match value {
            512 => SyscallCode::Write,
            513 => SyscallCode::Exit,
            1024 => SyscallCode::ReadFromPrivateInput,
            1025 => SyscallCode::CycleCount,
            _ => return Err(VMError::UnimplementedSyscall(value, pc)),
        };
        Ok(code)
    }
}

impl From<SyscallCode> for u32 {
    fn from(val: SyscallCode) -> Self {
        match val {
            SyscallCode::Write => 512,
            SyscallCode::Exit => 513,
            SyscallCode::ReadFromPrivateInput => 1024,
            SyscallCode::CycleCount => 1025,
        }
    }
}

/// Represents a system call instruction in the RISC-V emulator.
///
/// This struct encapsulates all the necessary information for executing a system call,
/// including the syscall code, arguments, and the result.
pub struct SyscallInstruction {
    /// The system call code, obtained from the "a7" (X17) register.
    ///
    /// This field determines which specific system call operation to perform.
    code: SyscallCode,

    /// The result of the system call, stored as a tuple of (Register, u32).
    ///
    /// The return register is always Register::X10 ("a0"), as per RISC-V convention.
    /// The second element is the actual result value:
    /// - Initially set to u32::MAX
    /// - 0 indicates success
    /// - otherwise error
    result: (Register, u32),

    /// Vector of up to 7 argument values for the system call.
    ///
    /// These correspond to registers X10 through X16 ("a0" through "a6").
    /// The number and meaning of arguments depend on the specific system call.
    args: Vec<u32>,
}

impl SyscallInstruction {
    pub fn decode(ins: &Instruction, cpu: &Cpu) -> Result<Self> {
        let opcode = ins.opcode.try_into()?;
        if BuiltinOpcode::ECALL != opcode {
            return Err(VMError::UnimplementedSyscall(
                ins.opcode.raw(),
                cpu.pc.value,
            ));
        }
        Ok(Self {
            code: SyscallCode::try_from(cpu.registers[Register::X17], cpu.pc.value)?,
            result: (Register::X10, u32::MAX),
            args: vec![
                cpu.registers[Register::X10],
                cpu.registers[Register::X11],
                cpu.registers[Register::X12],
                cpu.registers[Register::X13],
                cpu.registers[Register::X14],
                cpu.registers[Register::X15],
                cpu.registers[Register::X16],
            ],
        })
    }

    /// Executes the write syscall to output data to a file descriptor.
    ///
    /// This function currently only supports writing to standard output (stdout).
    /// It reads data from memory and prints it to the console.
    fn execute_write(
        &mut self,
        memory: &impl MemoryProcessor,
        fd: u32,
        buf_addr: u32,
        count: u32,
    ) -> Result<()> {
        // Write to STDOUT: (fd == 1)
        if fd == 1 {
            let buffer = memory.read_bytes(buf_addr, count as _)?;
            print!("{}", String::from_utf8_lossy(&buffer));
            self.result.1 = count;
        } else {
            // Return -1
            self.result.1 = u32::MAX;
        }
        Ok(())
    }

    /// Executes the exit syscall to terminate the program.
    ///
    /// This function sets the exit code and signals the VM to terminate execution.
    fn execute_exit(&mut self, error_code: u32) -> Result<()> {
        self.result.1 = error_code;
        Err(VMError::VMExited)
    }

    /// Executes the cycle count syscall for profiling function execution time.
    ///
    /// This function reads a label from memory, processes it, and updates the cycle tracker
    /// in the emulator. The label format should be "<marker>#<function_name>", where
    /// marker is either '^' (start) or '$' (end), marker is inspired from Regular Expression.
    fn execute_cyclecount(&mut self, emulator: &mut Emulator, buf: u32, buflen: u32) -> Result<()> {
        let buf = emulator.data_memory.read_bytes(buf, buflen as _)?;

        // Convert buffer to string and split it into marker and function name
        let label = String::from_utf8_lossy(&buf).to_string();
        let (marker, fn_name) = label
            .split_once('#')
            .ok_or_else(|| VMError::InvalidProfileLabel(label.clone()))?
            .to_owned();

        // Ensure the marker is either '^' (start) or '$' (end)
        if !matches!(marker, "^" | "$") {
            return Err(VMError::InvalidProfileLabel(label));
        }

        // Get or create an entry in the cycle tracker for this function
        let entry = emulator.cycle_tracker.entry(fn_name.to_string());

        match (marker, entry) {
            ("^", hash_map::Entry::Occupied(mut entry)) => {
                // Start marker for an existing entry: increment occurrence count
                entry.get_mut().1 += 1;
                self.result.1 = 0;
            }
            ("$", hash_map::Entry::Occupied(mut entry)) => {
                // End marker for an existing entry
                let (total_cycles, occurrence) = entry.get_mut();
                *occurrence -= 1;
                if *occurrence == 0 {
                    // If this is the last occurrence, calculate total cycles
                    *total_cycles = emulator.global_clock - *total_cycles;
                }
                self.result.1 = 0;
            }
            ("^", hash_map::Entry::Vacant(entry)) => {
                // Start marker for a new entry: initialize with current clock and occurrence of 1
                entry.insert((emulator.global_clock, 1));
                self.result.1 = 0;
            }
            ("$", hash_map::Entry::Vacant(_)) => {
                // End marker for a non-existent entry: this is an error
                self.result.1 = u32::MAX;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn execute_read_from_private_input(
        &mut self,
        private_input_memory: &mut VecDeque<u8>,
    ) -> Result<()> {
        self.result.1 = private_input_memory
            .pop_front()
            .map_or(u32::MAX, |v| v as u32);
        Ok(())
    }

    // Reads from memory for syscall instruction.
    pub fn memory_read(&mut self, _memory: &impl MemoryProcessor) -> Result<()> {
        Ok(())
    }

    /// Executes the syscall instruction.
    ///
    /// This function performs the following operations:
    /// 1. Reads CPU registers
    /// 2. Interacts with fields in the `Emulator` struct, but not CPU and memory.
    ///
    /// Note:
    /// - Any modifications to CPU registers must be done using the `write_back` function.
    /// - Any modifications to memory must be done using the `memory_write` function.
    /// `Result<()>` - Ok if the syscall executed successfully, or an error if it failed
    pub fn execute(&mut self, emulator: &mut Emulator) -> Result<()> {
        match self.code {
            SyscallCode::Write => {
                let fd = self.args[0];
                let buf = self.args[1];
                let count = self.args[2];
                self.execute_write(&emulator.data_memory, fd, buf, count)
            }

            SyscallCode::CycleCount => {
                let buf = self.args[0];
                let buflen = self.args[1];
                self.execute_cyclecount(emulator, buf, buflen)
            }

            SyscallCode::Exit => {
                let error_code = self.args[0];
                self.execute_exit(error_code)
            }

            SyscallCode::ReadFromPrivateInput => {
                self.execute_read_from_private_input(&mut emulator.private_input_memory)
            }
        }
    }

    // Writes to memory for syscall instructions.
    pub fn memory_write(&self, _memory: &mut impl MemoryProcessor) -> Result<()> {
        Ok(())
    }

    // All the write back to registers is done in the write_back function
    pub fn write_back(&self, cpu: &mut Cpu) {
        cpu.registers.write(self.result.0, self.result.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::riscv::{BuiltinOpcode, InstructionType, Opcode};

    fn setup_emulator() -> Emulator {
        Emulator::default()
    }

    #[test]
    fn test_execute_write_stdout() {
        let fd = 1;
        let buf = b"Hello";
        let buf_addr = 0;
        let buf_len = buf.len();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::Write,
            result: (Register::X10, 0),
            args: vec![fd, buf_addr, buf_len as _, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_write(&emulator.data_memory, fd, buf_addr, buf_len as _)
            .expect("Failed to execute write syscall");
        syscall_instruction.write_back(&mut emulator.cpu);

        assert_eq!(emulator.cpu.registers.read(Register::X10), buf_len as u32);
    }

    #[test]
    fn test_execute_write_invalid_fd() {
        let fd = 2; // Invalid fd
        let buf = b"Hello";
        let buf_addr = 0;
        let buf_len = buf.len();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::Write,
            result: (Register::X10, 0),
            args: vec![fd, buf_addr, buf_len as _, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_write(&emulator.data_memory, fd, buf_addr, buf_len as _)
            .expect("Failed to execute write syscall");
        syscall_instruction.write_back(&mut emulator.cpu);

        assert_eq!(emulator.cpu.registers.read(Register::X10), u32::MAX);
    }

    #[test]
    fn test_execute_exit() {
        let error_code = 42;
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::Exit,
            result: (Register::X10, 0),
            args: vec![error_code, 0, 0, 0, 0, 0, 0],
        };

        let result = syscall_instruction.execute_exit(error_code);
        syscall_instruction.write_back(&mut emulator.cpu);

        assert!(matches!(result, Err(VMError::VMExited)));
        assert_eq!(emulator.cpu.registers.read(Register::X10), error_code);
    }

    #[test]
    fn test_execute_cyclecount() {
        let buf = b"^#fib";
        let buf_addr = 0;
        let buf_len = buf.len();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::CycleCount,
            result: (Register::X10, 0),
            args: vec![buf_addr, buf_len as _, 0, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_cyclecount(&mut emulator, buf_addr, buf_len as _)
            .expect("Failed to execute cyclecount syscall");
        syscall_instruction.write_back(&mut emulator.cpu);

        assert_eq!(emulator.cpu.registers.read(Register::X10), 0);
        assert!(emulator.cycle_tracker.contains_key("fib"));

        // Test end marker
        let buf = b"$#fib";
        let buf_addr = 0x100;
        emulator.global_clock = 100;
        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_cyclecount(&mut emulator, buf_addr, buf_len as _)
            .expect("Failed to execute cyclecount syscall");
        syscall_instruction.write_back(&mut emulator.cpu);

        assert_eq!(emulator.cpu.registers.read(Register::X10), 0);
        assert_eq!(emulator.cycle_tracker["fib"].0, 100);
        assert_eq!(emulator.cycle_tracker["fib"].1, 0);
    }

    #[test]
    fn test_syscall_decode() {
        let mut cpu = Cpu::default();
        // Write syscall
        cpu.registers.write(Register::X17, 512);
        cpu.registers.write(Register::X10, 1);
        cpu.registers.write(Register::X11, 100);
        cpu.registers.write(Register::X12, 5);

        let instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::ECALL),
            0,
            1,
            2,
            InstructionType::IType,
        ); // Assuming this creates an ECALL instruction

        let syscall = SyscallInstruction::decode(&instruction, &cpu).unwrap();
        assert!(matches!(syscall.code, SyscallCode::Write));
        assert_eq!(syscall.args[0], 1);
        assert_eq!(syscall.args[1], 100);
        assert_eq!(syscall.args[2], 5);
    }

    #[test]
    fn test_execute_read_from_private_input() {
        let mut private_input_memory = VecDeque::from(vec![1, 2, 3]);
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::ReadFromPrivateInput,
            result: (Register::X10, 0),
            args: vec![],
        };

        // Test reading values
        for expected_value in 1..=3 {
            syscall_instruction
                .execute_read_from_private_input(&mut private_input_memory)
                .expect("Failed to execute read from private input");
            assert_eq!(syscall_instruction.result.1, expected_value);
        }

        // Test reading when private input is empty
        syscall_instruction
            .execute_read_from_private_input(&mut private_input_memory)
            .expect("Failed to execute read from private input");
        assert_eq!(syscall_instruction.result.1, u32::MAX);
    }
}
