//! Represents the Central Processing Unit (CPU) of the RISC-V emulator.
//!
//! This struct contains all the essential components and state information
//! needed to emulate a RISC-V processor.

use super::registerfile::RegisterFile;

use nexus_common::cpu::PC;
pub use nexus_common::cpu::{InstructionExecutor, InstructionState};
use nexus_common::cpu::{Processor, Registers};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// The general purpose 32-bit registers.
    pub registers: RegisterFile,

    /// The current program counter (PC).
    pub pc: PC,

    /// The cycle counter.
    pub cycles: u64,

    /// A snapshot of the CPU state at the beginning of the current block.
    pub snapshot: (RegisterFile, PC),
}

impl Processor for Cpu {
    fn registers(&self) -> &impl Registers {
        &self.registers
    }

    fn registers_mut(&mut self) -> &mut impl Registers {
        &mut self.registers
    }

    fn pc(&self) -> &PC {
        &self.pc
    }

    fn pc_mut(&mut self) -> &mut PC {
        &mut self.pc
    }
}
