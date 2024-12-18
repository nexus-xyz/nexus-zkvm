use nexus_common::{
    cpu::{InstructionExecutor, InstructionResult, InstructionState, Processor, Registers},
    error::MemoryError,
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{instruction::Instruction, register::Register},
};

use nexus_precompiles::{PrecompileCircuit, PrecompileInstruction, PrecompileMetadata};

pub struct DummyCircuit;

#[derive(Default)]
pub struct DummyDiv {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionState for DummyDiv {
    fn execute(&mut self) {
        self.rd.1 = self.rs1 / self.rs2;
    }

    fn memory_read(&mut self, _memory: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <Self as InstructionState>::readless()
    }

    fn memory_write(&self, _memory: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <Self as InstructionState>::writeless()
    }

    fn write_back(&self, cpu: &mut impl Processor) -> InstructionResult {
        cpu.registers_mut().write(self.rd.0, self.rd.1);
        Some(self.rd.1)
    }
}

impl InstructionExecutor for DummyDiv {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: registers[Register::from(ins.op_c as u8)],
        }
    }
}

impl PrecompileCircuit for DummyCircuit {}

impl PrecompileInstruction for DummyDiv {
    fn metadata() -> PrecompileMetadata {
        PrecompileMetadata {
            author: "Author",
            name: "DummyHash",
            description: "A dummy hash precompile",
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
        }
    }

    fn circuit() -> impl PrecompileCircuit {
        DummyCircuit {}
    }

    fn native_call(rs1: u32, rs2: u32) -> u32 {
        rs1 / rs2
    }
}
