use nexus_common::cpu::{InstructionExecutor, InstructionState};
use nexus_precompiles::{PrecompileCircuit, PrecompileInstruction, PrecompileMetadata};

pub struct DummyCircuit;

#[derive(Default)]
pub struct DummyDiv;

impl InstructionState for DummyDiv {
    fn execute(&mut self) {
        todo!()
    }

    fn memory_read(
        &mut self,
        _memory: &impl nexus_common::memory::MemoryProcessor,
    ) -> Result<nexus_common::memory::LoadOps, nexus_common::error::MemoryError> {
        todo!()
    }

    fn memory_write(
        &self,
        _memory: &mut impl nexus_common::memory::MemoryProcessor,
    ) -> Result<nexus_common::memory::StoreOps, nexus_common::error::MemoryError> {
        todo!()
    }

    fn write_back(
        &self,
        _cpu: &mut impl nexus_common::cpu::Processor,
    ) -> nexus_common::cpu::InstructionResult {
        todo!()
    }
}

impl InstructionExecutor for DummyDiv {
    type InstructionState = Self;

    fn decode(
        _ins: &nexus_common::riscv::instruction::Instruction,
        _registers: &impl nexus_common::cpu::Registers,
    ) -> Self {
        todo!()
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

#[macro_export]
macro_rules! generate_instruction_caller {
    ($path:path) => {
        trait DummyDivCaller {
            fn div(dividend: u32, divisor: u32) -> u32;
        }

        impl DummyDivCaller for $path {
            fn div(dividend: u32, divisor: u32) -> u32 {
                Self::emit_instruction(dividend, divisor, 0)
            }
        }
    };
}
