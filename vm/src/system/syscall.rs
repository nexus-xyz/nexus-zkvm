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
//! 2. Executing various syscalls, such as:
//!    - Write: Output data to a file descriptor (currently only supports stdout).
//!    - Exit: Terminate the program with a specified error code.
//!    - CycleCount: Profile function execution time.
//!    - ReadFromPrivateInput: Read data from a private input tape.
//!    - OverwriteStackPointer: Modify the stack pointer based on memory layout.
//!    - OverwriteHeapPointer: Modify the heap pointer based on memory layout.
//! 3. Handling memory interactions for syscalls.
//! 4. Writing back results to CPU registers.
//!
//! This implementation follows a clear separation of concerns, with distinct methods for
//! instruction decoding, execution, memory operations, and CPU state updates. This design
//! allows for easier testing, maintenance, and potential future extensions of the syscall
//! system.
use std::collections::{hash_map, HashSet, VecDeque};

use nexus_common::cpu::Registers;

use crate::{
    cpu::Cpu,
    emulator::{memory_stats::MemoryStats, Executor, LinearMemoryLayout},
    error::{Result, VMErrorKind},
    memory::{LoadOp, MemoryProcessor, StoreOp},
    riscv::{BuiltinOpcode, Instruction, Register},
};

pub enum SyscallCode {
    // Syscall code defines opcodes start from 0x200
    Write = 0x200, // Is converted to NOP for tracing
    Exit = 0x201,
    // zkVM specific syscall opcodes start from 0x400
    ReadFromPrivateInput = 0x400,
    CycleCount = 0x401, // Is converted to NOP for tracing
    OverwriteStackPointer = 0x402,
    OverwriteHeapPointer = 0x403,
    ReadFromAuxiliaryInput = 0x404,
    MemoryAdvise = 0x405, // Is converted to NOP for tracing
}

impl SyscallCode {
    fn try_from(value: u32, pc: u32) -> Result<Self> {
        let code = match value {
            0x200 => SyscallCode::Write,
            0x201 => SyscallCode::Exit,
            0x400 => SyscallCode::ReadFromPrivateInput,
            0x401 => SyscallCode::CycleCount,
            0x402 => SyscallCode::OverwriteStackPointer,
            0x403 => SyscallCode::OverwriteHeapPointer,
            //0x404 => SyscallCode::ReadFromAuxiliaryInput,
            0x405 => SyscallCode::MemoryAdvise,
            _ => return Err(VMErrorKind::UnimplementedSyscall(value, pc))?,
        };
        Ok(code)
    }
}

impl From<u32> for SyscallCode {
    fn from(value: u32) -> Self {
        match value {
            0x200 => SyscallCode::Write,
            0x201 => SyscallCode::Exit,
            0x400 => SyscallCode::ReadFromPrivateInput,
            0x401 => SyscallCode::CycleCount,
            0x402 => SyscallCode::OverwriteStackPointer,
            0x403 => SyscallCode::OverwriteHeapPointer,
            0x404 => SyscallCode::ReadFromAuxiliaryInput,
            0x405 => SyscallCode::MemoryAdvise,
            _ => panic!("Invalid syscall code"),
        }
    }
}

impl From<SyscallCode> for u32 {
    fn from(val: SyscallCode) -> Self {
        match val {
            SyscallCode::Write => 0x200,
            SyscallCode::Exit => 0x201,
            SyscallCode::ReadFromPrivateInput => 0x400,
            SyscallCode::CycleCount => 0x401,
            SyscallCode::OverwriteStackPointer => 0x402,
            SyscallCode::OverwriteHeapPointer => 0x403,
            SyscallCode::ReadFromAuxiliaryInput => 0x404,
            SyscallCode::MemoryAdvise => 0x405,
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
    /// The return register is sometimes Register::X10 ("a0") and sometimes X2 as per RISC-V convention.
    /// The second element is the actual result value.
    /// Some syscalls don't modify registers, for them result is None.
    result: Option<(Register, u32)>,

    /// Vector of up to 7 argument values for the system call.
    ///
    /// These correspond to registers X10 through X16 ("a0" through "a6").
    /// The number and meaning of arguments depend on the specific system call.
    args: Vec<u32>,
}

impl SyscallInstruction {
    pub fn decode(ins: &Instruction, cpu: &Cpu) -> Result<Self> {
        if !matches!(ins.opcode.builtin(), Some(BuiltinOpcode::ECALL)) {
            return Err(VMErrorKind::InstructionNotSyscall(
                ins.opcode.clone(),
                cpu.pc.value,
            ))?;
        }
        Ok(Self {
            code: SyscallCode::try_from(cpu.registers[Register::X17], cpu.pc.value)?,
            result: Some((Register::X10, u32::MAX)),
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
        logs: &mut Option<Vec<Vec<u8>>>,
        memory: &impl MemoryProcessor,
        fd: u32,
        buf_addr: u32,
        count: u32,
    ) -> Result<()> {
        // Write to STDOUT: (fd == 1)
        if fd == 1 {
            let buffer = memory.read_bytes(buf_addr, count as _)?;

            if let Some(logger) = logs {
                logger.push(buffer);
            } else {
                print!("{}", String::from_utf8_lossy(&buffer));
            }

            self.result = Some((Register::X10, count));
        } else {
            // Return -1
            self.result = Some((Register::X10, u32::MAX));
        }
        Ok(())
    }

    /// Executes the exit syscall to terminate the program.
    ///
    /// This function sets the exit code and signals the VM to terminate execution.
    fn execute_exit(&mut self, error_code: u32) -> Result<()> {
        self.result = Some((Register::X10, error_code));
        Err(VMErrorKind::VMExited(error_code))?
    }

    /// Executes the cycle count syscall for profiling function execution time.
    ///
    /// This function reads a label from memory, processes it, and updates the cycle tracker
    /// in the emulator. The label format should be "<marker>#<function_name>", where
    /// marker is either '^' (start) or '$' (end), marker is inspired from Regular Expression.
    fn execute_cyclecount(
        &mut self,
        executor: &mut Executor,
        memory: &impl MemoryProcessor,
        buf: u32,
        buflen: u32,
    ) -> Result<()> {
        let buf = memory.read_bytes(buf, buflen as _)?;

        // Convert buffer to string and split it into marker and function name
        let label = String::from_utf8_lossy(&buf).to_string();
        let (marker, fn_name) = match label.split_once('#') {
            Some(parts) => parts,
            None => return Err(VMErrorKind::InvalidProfileLabel(label))?,
        };

        // Ensure the marker is either '^' (start) or '$' (end)
        if !matches!(marker, "^" | "$") {
            return Err(VMErrorKind::InvalidProfileLabel(label))?;
        }

        // Get or create an entry in the cycle tracker for this function
        let entry = executor.cycle_tracker.entry(fn_name.to_string());

        match (marker, entry) {
            ("^", hash_map::Entry::Occupied(mut entry)) => {
                // Start marker for an existing entry: increment occurrence count
                entry.get_mut().1 += 1;
                self.result = None;
            }
            ("$", hash_map::Entry::Occupied(mut entry)) => {
                // End marker for an existing entry
                let (total_cycles, occurrence) = entry.get_mut();
                *occurrence -= 1;
                if *occurrence == 0 {
                    // If this is the last occurrence, calculate total cycles
                    *total_cycles = executor.global_clock - *total_cycles;
                }
                self.result = None;
            }
            ("^", hash_map::Entry::Vacant(entry)) => {
                // Start marker for a new entry: initialize with current clock and occurrence of 1
                entry.insert((executor.global_clock, 1));
                self.result = None;
            }
            ("$", hash_map::Entry::Vacant(_)) => {
                // End marker for a non-existent entry: this is an error
                self.result = Some((Register::X10, u32::MAX));
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn execute_read_from_private_input(
        &mut self,
        private_input_tape: &mut VecDeque<u8>,
    ) -> Result<()> {
        self.result = Some((
            Register::X10,
            private_input_tape
                .pop_front()
                .map_or(u32::MAX, |v| v as u32),
        ));
        Ok(())
    }

    fn execute_overwrite_stack_pointer(
        &mut self,
        memory_layout: Option<LinearMemoryLayout>,
    ) -> Result<()> {
        if let Some(layout) = memory_layout {
            self.result = Some((Register::X2, layout.stack_top()));
        }

        Ok(())
    }

    fn execute_overwrite_heap_pointer(
        &mut self,
        memory_layout: Option<LinearMemoryLayout>,
    ) -> Result<()> {
        if let Some(layout) = memory_layout {
            self.result = Some((Register::X10, layout.heap_start()));
        } else {
            self.result = Some((Register::X10, 0)); // 0 indicates no overwrite is necessary
        }

        Ok(())
    }

    fn execute_allocate_heap(
        &mut self,
        addr: u32,
        len: u32,
        memory_stats: Option<&mut MemoryStats>,
    ) -> Result<()> {
        if let Some(stats) = memory_stats {
            stats.register_heap_allocation(addr, len);
        }
        Ok(())
    }

    // Reads from memory for syscall instruction.
    pub fn memory_read(&mut self, _memory: &impl MemoryProcessor) -> Result<HashSet<LoadOp>> {
        Ok(HashSet::<LoadOp>::new())
    }

    /// Executes the syscall instruction.
    ///
    /// This function performs the following operations:
    /// 1. Reads CPU registers
    /// 2. Interacts with fields in the `Emulator` struct, and reads but does not write to memory.
    ///
    /// Note:
    /// - Any modifications to CPU registers must be done using the `write_back` function.
    /// - Any modifications to memory must be done using the `memory_write` function.
    ///   `Result<()>` - Ok if the syscall executed successfully, or an error if it failed
    pub fn execute(
        &mut self,
        executor: &mut Executor,
        memory: &impl MemoryProcessor,
        memory_layout: Option<LinearMemoryLayout>,
        memory_stats: Option<&mut MemoryStats>,
        force_second_pass: bool,
    ) -> Result<()> {
        let second_pass = memory_layout.is_some() || force_second_pass;
        match self.code {
            SyscallCode::Write => {
                // No-op on second pass.
                if second_pass {
                    self.result = None;
                    return Ok(());
                }

                let fd = self.args[0];
                let buf = self.args[1];
                let count = self.args[2];
                self.execute_write(&mut executor.logs, memory, fd, buf, count)
            }

            SyscallCode::CycleCount => {
                // no-op on second pass
                if second_pass {
                    self.result = None;
                    return Ok(());
                }

                let buf = self.args[0];
                let buflen = self.args[1];
                self.execute_cyclecount(executor, memory, buf, buflen)
            }

            SyscallCode::Exit => {
                // no result written on second pass
                if second_pass {
                    self.result = None;
                    // but we still need to return an error to stop the VM
                    let error_code = self.args[0];
                    return Err(VMErrorKind::VMExited(error_code))?;
                }
                let error_code = self.args[0];
                self.execute_exit(error_code)
            }

            SyscallCode::ReadFromPrivateInput => {
                self.execute_read_from_private_input(&mut executor.private_input_tape)
            }

            SyscallCode::OverwriteStackPointer => {
                self.execute_overwrite_stack_pointer(memory_layout)
            }

            SyscallCode::OverwriteHeapPointer => self.execute_overwrite_heap_pointer(memory_layout),

            SyscallCode::ReadFromAuxiliaryInput => unreachable!(), // unreachable since parsing of the code will fail

            SyscallCode::MemoryAdvise => {
                // No-op on second pass.
                if second_pass {
                    self.result = None;
                    return Ok(());
                }

                let addr = self.args[0];
                let len = self.args[1];

                self.execute_allocate_heap(addr, len, memory_stats)
            }
        }
    }

    // Writes to memory for syscall instructions.
    pub fn memory_write(&self, _memory: &mut impl MemoryProcessor) -> Result<HashSet<StoreOp>> {
        Ok(HashSet::<StoreOp>::new())
    }

    // All the write back to registers is done in the write_back function
    pub fn write_back(&self, cpu: &mut Cpu) {
        if let Some((reg, value)) = self.result {
            cpu.registers.write(reg, value);
        }
    }

    // Read the result
    pub fn get_result(&self) -> Option<(Register, u32)> {
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::HarvardEmulator;
    use crate::memory::{VariableMemory, RW};
    use crate::riscv::{BuiltinOpcode, Opcode};

    fn setup_emulator() -> HarvardEmulator {
        let mut emul = HarvardEmulator::default();
        emul.data_memory
            .add_variable(VariableMemory::<RW>::default())
            .unwrap();

        emul
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
            result: Some((Register::X10, 0)),
            args: vec![fd, buf_addr, buf_len as _, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_write(&mut None, &emulator.data_memory, fd, buf_addr, buf_len as _)
            .expect("Failed to execute write syscall");
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(
            emulator.executor.cpu.registers.read(Register::X10),
            buf_len as u32
        );
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
            result: Some((Register::X10, 0)),
            args: vec![fd, buf_addr, buf_len as _, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_write(&mut None, &emulator.data_memory, fd, buf_addr, buf_len as _)
            .expect("Failed to execute write syscall");
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(
            emulator.executor.cpu.registers.read(Register::X10),
            u32::MAX
        );
    }

    #[test]
    fn test_execute_exit() {
        let error_code = 42;
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::Exit,
            result: Some((Register::X10, 0)),
            args: vec![error_code, 0, 0, 0, 0, 0, 0],
        };

        let result = syscall_instruction.execute_exit(error_code);
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(
            result.unwrap_err().source,
            VMErrorKind::VMExited(error_code)
        );
    }

    #[test]
    fn test_execute_overwrite_stack_pointer() {
        let memory_layout = LinearMemoryLayout::default();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::OverwriteStackPointer,
            result: Some((Register::X10, 0)),
            args: vec![0, 0, 0, 0, 0, 0, 0],
        };

        let _ = syscall_instruction.execute_overwrite_stack_pointer(Some(memory_layout));
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(
            emulator.executor.cpu.registers.read(Register::X2),
            memory_layout.stack_top()
        );
    }

    #[test]
    fn test_execute_overwrite_heap_pointer() {
        let memory_layout = LinearMemoryLayout::default();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::OverwriteStackPointer,
            result: Some((Register::X10, 0)),
            args: vec![0, 0, 0, 0, 0, 0, 0],
        };

        let _ = syscall_instruction.execute_overwrite_heap_pointer(Some(memory_layout));
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(
            emulator.executor.cpu.registers.read(Register::X10),
            memory_layout.heap_start()
        );
    }

    #[test]
    fn test_execute_cyclecount() {
        let buf = b"^#fib";
        let buf_addr = 0;
        let buf_len = buf.len();
        let mut emulator = setup_emulator();
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::CycleCount,
            result: Some((Register::X10, 0)),
            args: vec![buf_addr, buf_len as _, 0, 0, 0, 0, 0],
        };

        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_cyclecount(
                &mut emulator.executor,
                &emulator.data_memory,
                buf_addr,
                buf_len as _,
            )
            .expect("Failed to execute cyclecount syscall");
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(emulator.executor.cpu.registers.read(Register::X10), 0);
        assert!(emulator.executor.cycle_tracker.contains_key("fib"));

        // Test end marker
        let buf = b"$#fib";
        let buf_addr = 0x100;
        emulator.executor.global_clock = 100;
        emulator
            .data_memory
            .write_bytes(buf_addr, buf)
            .expect("Failed to write to memory");
        syscall_instruction
            .execute_cyclecount(
                &mut emulator.executor,
                &emulator.data_memory,
                buf_addr,
                buf_len as _,
            )
            .expect("Failed to execute cyclecount syscall");
        syscall_instruction.write_back(&mut emulator.executor.cpu);

        assert_eq!(emulator.executor.cpu.registers.read(Register::X10), 0);
        assert_eq!(emulator.executor.cycle_tracker["fib"].0, 100);
        assert_eq!(emulator.executor.cycle_tracker["fib"].1, 0);
    }

    #[test]
    fn test_syscall_decode() {
        let mut cpu = Cpu::default();
        // Write syscall
        cpu.registers.write(Register::X17, 512);
        cpu.registers.write(Register::X10, 1);
        cpu.registers.write(Register::X11, 100);
        cpu.registers.write(Register::X12, 5);

        let instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 1, 2); // Assuming this creates an ECALL instruction

        let syscall = SyscallInstruction::decode(&instruction, &cpu).unwrap();
        assert!(matches!(syscall.code, SyscallCode::Write));
        assert_eq!(syscall.args[0], 1);
        assert_eq!(syscall.args[1], 100);
        assert_eq!(syscall.args[2], 5);
    }

    #[test]
    fn test_execute_read_from_private_input() {
        let mut private_input_tape = VecDeque::from(vec![1, 2, 3]);
        let mut syscall_instruction = SyscallInstruction {
            code: SyscallCode::ReadFromPrivateInput,
            result: Some((Register::X10, 0)),
            args: vec![],
        };

        // Test reading values
        for expected_value in 1..=3 {
            syscall_instruction
                .execute_read_from_private_input(&mut private_input_tape)
                .expect("Failed to execute read from private input");
            assert!(syscall_instruction
                .result
                .is_some_and(|(reg, value)| { reg == Register::X10 && value == expected_value }));
        }

        // Test reading when private input is empty
        syscall_instruction
            .execute_read_from_private_input(&mut private_input_tape)
            .expect("Failed to execute read from private input");
        assert!(syscall_instruction
            .result
            .is_some_and(|(reg, value)| { reg == Register::X10 && value == u32::MAX }));
    }
}
