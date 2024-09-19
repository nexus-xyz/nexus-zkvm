//! # Instruction Executor Module
//!
//! This module defines the instruction execution functionality for the RISC-V emulator.
//! It provides a centralized mapping of opcodes to their corresponding execution functions.
//!
//! ## Key Components
//!
//! - `InstructionExecutorFn`: A type alias for the instruction execution function signature.
//! - `INSTRUCTION_EXECUTOR`: A static, lazily initialized, thread-safe map of opcodes to execution functions.
//!
//! ## Instruction Categories
//!
//! The module organizes instructions into several categories:
//!
//! - ALU Instructions: Arithmetic and logical operations
//! - Memory Instructions: Load and store operations
//! - Branch Instructions: Conditional and unconditional jumps
//! - System Instructions: Special system-level operations
//!
//! ## Thread Safety
//!
//! The `INSTRUCTION_EXECUTOR` is wrapped in a `RwLock` to ensure thread-safe access and modification.
//! This allows multiple readers to access the executor map concurrently, while ensuring exclusive access for writers.
//! Always remember to properly acquire and release the appropriate lock when accessing or modifying the executor map:
//! - Use `read()` for read-only access
//! - Use `write()` when modifying the map
//!
//! ## Extensibility
//!
//! The emulator supports adding custom opcodes and their corresponding execution functions at runtime.
//! This feature allows for extending the instruction set without modifying the core emulator code.
//!
//! To add a new opcode:
//!
//! 1. Define a custom execution function that implements the `InstructionExecutorFn` signature.
//! 2. Use the `add_opcode` method of the `Emulator` struct to register the new opcode and its execution function.
//!
//! Example:
//!
//! ```rust
//! use nexus_vm::{cpu::Cpu, memory::Memory, emulator::Emulator, riscv::{Opcode, Instruction}, error::Result};
//!
//! let custom_opcode = Opcode::CUSTOM0;
//! let custom_function = |_cpu: &mut Cpu, _data_memory: &mut Memory, instruction: &Instruction| -> Result<()> {
//!     // Implement custom instruction logic here
//!     Ok(())
//! };
//! let mut emulator = Emulator::default().add_opcode(custom_opcode, custom_function).unwrap();
//! ```
//!
//! Note:
//! - The `add_opcode` method checks for duplicate opcodes and returns an error if the opcode already exists.
//! - Custom instructions can implement the `InstructionExecutor` trait for a more structured approach.
//! - The emulator prevents overwriting existing standard RISC-V instructions to maintain compatibility.
//!
//! ## Error Handling
//!
//! Execution functions return a `Result<()>`, allowing for proper error propagation throughout the emulator.
//! The `add_opcode` method also returns a `Result`, indicating success or failure in adding the new opcode.

use crate::{
    cpu::Cpu,
    error::Result,
    memory::Memory,
    riscv::{Instruction, Opcode},
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::RwLock;

use super::alu_instructions::{
    execute_add, execute_and, execute_div, execute_divu, execute_mul, execute_mulh, execute_mulhsu,
    execute_mulhu, execute_or, execute_rem, execute_remu, execute_sll, execute_slt, execute_sltu,
    execute_sra, execute_srl, execute_sub, execute_xor,
};

use super::memory_instructions::{
    execute_lb, execute_lbu, execute_lh, execute_lhu, execute_lw, execute_sb, execute_sh,
    execute_sw,
};

use super::branch_instructions::{
    execute_beq, execute_bge, execute_bgeu, execute_blt, execute_bltu, execute_bne, execute_jal,
    execute_jalr,
};

use super::system_instructions::{
    executable_auipc, execute_ecall, execute_lui, execute_nop, execute_unimplemented,
};

pub type InstructionExecutorFn = fn(&mut Cpu, &mut Memory, &Instruction) -> Result<()>;

pub static INSTRUCTION_EXECUTOR: Lazy<RwLock<HashMap<Opcode, InstructionExecutorFn>>> =
    Lazy::new(|| {
        let mut m = HashMap::new();

        // ALU instructions
        m.insert(Opcode::ADD, execute_add as InstructionExecutorFn);
        m.insert(Opcode::ADDI, execute_add as InstructionExecutorFn);
        m.insert(Opcode::AND, execute_and as InstructionExecutorFn);
        m.insert(Opcode::ANDI, execute_and as InstructionExecutorFn);
        m.insert(Opcode::OR, execute_or as InstructionExecutorFn);
        m.insert(Opcode::ORI, execute_or as InstructionExecutorFn);
        m.insert(Opcode::SLL, execute_sll as InstructionExecutorFn);
        m.insert(Opcode::SLLI, execute_sll as InstructionExecutorFn);
        m.insert(Opcode::SRL, execute_srl as InstructionExecutorFn);
        m.insert(Opcode::SRLI, execute_srl as InstructionExecutorFn);
        m.insert(Opcode::SRA, execute_sra as InstructionExecutorFn);
        m.insert(Opcode::SRAI, execute_sra as InstructionExecutorFn);
        m.insert(Opcode::SUB, execute_sub as InstructionExecutorFn);
        m.insert(Opcode::XOR, execute_xor as InstructionExecutorFn);
        m.insert(Opcode::XORI, execute_xor as InstructionExecutorFn);
        m.insert(Opcode::SLT, execute_slt as InstructionExecutorFn);
        m.insert(Opcode::SLTI, execute_slt as InstructionExecutorFn);
        m.insert(Opcode::SLTU, execute_sltu as InstructionExecutorFn);
        m.insert(Opcode::SLTIU, execute_sltu as InstructionExecutorFn);
        m.insert(Opcode::DIV, execute_div as InstructionExecutorFn);
        m.insert(Opcode::DIVU, execute_divu as InstructionExecutorFn);
        m.insert(Opcode::MUL, execute_mul as InstructionExecutorFn);
        m.insert(Opcode::MULHU, execute_mulhu as InstructionExecutorFn);
        m.insert(Opcode::MULH, execute_mulh as InstructionExecutorFn);
        m.insert(Opcode::MULHSU, execute_mulhsu as InstructionExecutorFn);
        m.insert(Opcode::REM, execute_rem as InstructionExecutorFn);
        m.insert(Opcode::REMU, execute_remu as InstructionExecutorFn);

        // STORE instructions
        m.insert(Opcode::SB, execute_sb as InstructionExecutorFn);
        m.insert(Opcode::SH, execute_sh as InstructionExecutorFn);
        m.insert(Opcode::SW, execute_sw as InstructionExecutorFn);

        // LOAD instructions
        m.insert(Opcode::LB, execute_lb as InstructionExecutorFn);
        m.insert(Opcode::LBU, execute_lbu as InstructionExecutorFn);
        m.insert(Opcode::LH, execute_lh as InstructionExecutorFn);
        m.insert(Opcode::LHU, execute_lhu as InstructionExecutorFn);
        m.insert(Opcode::LW, execute_lw as InstructionExecutorFn);

        // BRANCH instructions
        m.insert(Opcode::BEQ, execute_beq as InstructionExecutorFn);
        m.insert(Opcode::BNE, execute_bne as InstructionExecutorFn);
        m.insert(Opcode::BLT, execute_blt as InstructionExecutorFn);
        m.insert(Opcode::BLTU, execute_bltu as InstructionExecutorFn);
        m.insert(Opcode::BGE, execute_bge as InstructionExecutorFn);
        m.insert(Opcode::BGEU, execute_bgeu as InstructionExecutorFn);
        m.insert(Opcode::JAL, execute_jal as InstructionExecutorFn);
        m.insert(Opcode::JALR, execute_jalr as InstructionExecutorFn);

        // LUI and AIUPC instructions
        m.insert(Opcode::LUI, execute_lui as InstructionExecutorFn);
        m.insert(Opcode::AUIPC, executable_auipc as InstructionExecutorFn);

        // NOP
        m.insert(Opcode::NOP, execute_nop as InstructionExecutorFn);

        // ECALL
        m.insert(Opcode::ECALL, execute_ecall as InstructionExecutorFn);

        // FENCE & EBREAK
        m.insert(
            Opcode::FENCE,
            execute_unimplemented as InstructionExecutorFn,
        );
        m.insert(
            Opcode::UNIMPL,
            execute_unimplemented as InstructionExecutorFn,
        );
        m.insert(
            Opcode::EBREAK,
            execute_unimplemented as InstructionExecutorFn,
        );

        RwLock::new(m)
    });
