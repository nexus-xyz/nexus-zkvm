use blake2::{digest::consts::U4, Blake2s, Blake2sVar, Blake2sVarCore, Digest};
use nexus_common::{
    cpu::{InstructionExecutor, InstructionResult, InstructionState, Processor, Registers},
    error::MemoryError,
    memory::{LoadOp, LoadOps, MemAccessSize, MemoryProcessor, StoreOps},
    riscv::{instruction::Instruction, register::Register},
};

use nexus_precompiles::{PrecompileCircuit, PrecompileInstruction, PrecompileMetadata};

pub struct DummyCircuit;

#[derive(Default)]
pub struct DummyHash {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
    data: Vec<u8>,
}

impl InstructionState for DummyHash {
    fn execute(&mut self) {
        let mut hasher = Blake2s::<U4>::new();
        hasher.update(&self.data);
        let hash: [u8; 4] = hasher.finalize().into();

        self.rd.1 = u32::from_le_bytes(hash);
    }

    fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        let mut buf = Vec::<u8>::with_capacity(self.rs2 as usize);
        let mut load_ops = LoadOps::default();

        // If you wanted to improve prover & VM performance, you could do this word-wise (then
        // half-word-wise, then byte-wise) instead of byte-wise. This is bytewise purely for the
        // sake of simplicity.
        for addr in self.rs1..(self.rs1 + self.rs2 as u32) {
            let load_op = memory.read(addr, MemAccessSize::Byte)?;
            load_ops.insert(load_op);

            let LoadOp::Op(_, _, value) = load_op;
            buf.push(value as u8);
        }

        self.data = buf;

        Ok(load_ops)
    }

    fn memory_write(&self, _memory: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <Self as InstructionState>::writeless()
    }

    fn write_back(&self, cpu: &mut impl Processor) -> InstructionResult {
        cpu.registers_mut().write(self.rd.0, self.rd.1);
        Some(self.rd.1)
    }
}

impl InstructionExecutor for DummyHash {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: registers[Register::from(ins.op_c as u8)],
            data: Vec::new(),
        }
    }
}

impl PrecompileCircuit for DummyCircuit {}

impl PrecompileInstruction for DummyHash {
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

    fn native_call(_rs1: u32, _rs2: u32) -> u32 {
        // Can't implement memory reading in the native environment (even if we were willing to do
        // unsafe C-style intptr_t things, native calls are almost always in 64-bit environments
        // anyway). Instead, just return 0 to indicate a no-op. Making this workable would be an
        // interesting project but ultimately isn't worth the effort right now.
        0
    }
}
