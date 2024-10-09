use crate::cpu::instructions::macros::implement_store_instruction;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{MemAccessSize, MemoryProcessor},
    riscv::Instruction,
};
use nexus_common::cpu::{Processor, Registers};

pub struct SbInstruction {
    rd: u32,
    rs1: u32,
    imm: u32,
}

implement_store_instruction!(SbInstruction, MemAccessSize::Byte);

#[cfg(test)]
mod tests {
    use nexus_common::error::MemoryError;

    use super::*;
    use crate::cpu::state::Cpu;
    use crate::memory::{VariableMemory, RW};
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    fn setup_memory() -> VariableMemory<RW> {
        VariableMemory::<RW>::default()
    }

    #[test]
    fn test_sb_positive_value() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);
        cpu.registers.write(Register::X2, 0x7F);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SB),
            2,
            1,
            0,
            InstructionType::SType,
        );
        let instruction = SbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_write(&mut memory).unwrap();

        assert_eq!(memory.read(0x1000, MemAccessSize::Byte).unwrap(), 0x7F);
    }

    #[test]
    fn test_sb_negative_value() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);
        cpu.registers.write(Register::X2, 0xFFFFFF80); // -128 in two's complement

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SB),
            2,
            1,
            1,
            InstructionType::SType,
        );
        let instruction = SbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_write(&mut memory).unwrap();

        assert_eq!(memory.read(0x1001, MemAccessSize::Byte).unwrap(), 0x80);
    }

    #[test]
    fn test_sb_max_negative_value() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);
        cpu.registers.write(Register::X2, 0xFFFFFFFF); // -1 in two's complement

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SB),
            2,
            1,
            2,
            InstructionType::SType,
        );
        let instruction = SbInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_write(&mut memory).unwrap();

        assert_eq!(memory.read(0x1002, MemAccessSize::Byte).unwrap(), 0xFF);
    }

    #[test]
    fn test_sb_overflow() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, 0xAA);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SB),
            2,
            1,
            1,
            InstructionType::SType,
        );
        let instruction = SbInstruction::decode(&bare_instruction, &cpu.registers);

        let result = instruction.memory_write(&mut memory);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MemoryError::AddressCalculationOverflow
        ));
    }

    // TODO: depending on the memory model, we need to test out of bound memory access
}
