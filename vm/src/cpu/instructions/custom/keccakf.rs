use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOp, LoadOps, MemAccessSize, MemoryProcessor, StoreOps},
    riscv::Instruction,
};
use nexus_common::{
    constants::WORD_SIZE,
    cpu::{Processor, Registers},
};
pub struct KeccakFInstruction {
    rs1: u32,
    state: [u64; 25],
}

impl InstructionState for KeccakFInstruction {
    fn memory_read(
        &mut self,
        memory: &impl MemoryProcessor,
    ) -> Result<LoadOps, nexus_common::error::MemoryError> {
        let address = self.rs1;

        let mut loads = LoadOps::default();
        for i in 0usize..25 {
            let mut value = 0u64;
            for j in 0..2 {
                let addr_offset = (2 * i + j) * WORD_SIZE;
                let op = memory.read(address + addr_offset as u32, MemAccessSize::Word)?;
                loads.insert(op);

                let LoadOp::Op(.., v) = op;
                value += u64::from(v) << (j * 32);
            }
            self.state[i] = value;
        }

        Ok(loads)
    }

    fn memory_write(
        &self,
        memory: &mut impl MemoryProcessor,
    ) -> Result<StoreOps, nexus_common::error::MemoryError> {
        let mask: u64 = (1 << 32) - 1;
        let address = self.rs1;

        let mut stores = StoreOps::default();
        for i in 0usize..25 {
            let mut value = self.state[i];
            for j in 0..2 {
                let limb = (value & mask) as u32;
                value >>= 32;

                let addr_offset = (2 * i + j) * WORD_SIZE;
                let op = memory.write(address + addr_offset as u32, MemAccessSize::Word, limb)?;
                stores.insert(op);
            }
        }

        Ok(stores)
    }

    fn execute(&mut self) {
        tiny_keccak::keccakf(&mut self.state);
    }

    fn write_back(&self, _cpu: &mut impl Processor) -> Option<u32> {
        None
    }
}

impl InstructionExecutor for KeccakFInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rs1: registers[ins.op_a],
            state: [0u64; 25],
        }
    }
}

#[cfg(test)]
mod tests {
    use nexus_common::{
        memory::RW,
        riscv::{register::Register, Opcode},
    };

    use crate::{cpu::Cpu, memory::VariableMemory};

    use super::*;

    #[test]
    fn test_keccakf() {
        let mut cpu = Cpu::default();
        let mut memory = VariableMemory::<RW>::default();

        let addr = 0x1000;
        cpu.registers.write(Register::X1, addr);

        let bare_instruction = Instruction::new_ir(
            Opcode::new(0b1011010, Some(0b000), None, "keccakf"),
            1,
            0,
            0,
        );
        let mut instruction = KeccakFInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).expect("read failed");
        instruction.execute();
        instruction.memory_write(&mut memory).expect("write failed");

        let state = {
            let mut state = vec![];
            let bytes = memory
                .segment_bytes(addr, Some(addr + (25 * 2 - 1) * WORD_SIZE as u32))
                .expect("segment read failed");
            for lane in bytes.chunks(8) {
                state.push(u64::from_le_bytes(
                    lane.try_into().expect("invalid lane size"),
                ));
            }
            state
        };
        let mut expected = [0u64; 25];
        tiny_keccak::keccakf(&mut expected);

        assert_eq!(state, expected);
    }
}
