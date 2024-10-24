use crate::cpu::instructions::macros::implement_store_instruction;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemAccessSize, MemoryProcessor, StoreOps},
    riscv::Instruction,
};
use nexus_common::cpu::{Processor, Registers};

pub struct SwInstruction {
    rd: u32,
    rs1: u32,
    imm: u32,
}

implement_store_instruction!(SwInstruction, MemAccessSize::Word);

#[cfg(test)]
mod tests {
    use nexus_common::error::MemoryError;

    use super::*;
    use crate::cpu::state::Cpu;
    use crate::memory::{LoadOp, VariableMemory, RW};
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    fn setup_memory() -> VariableMemory<RW> {
        VariableMemory::<RW>::default()
    }

    #[test]
    fn test_sw_positive_value() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);
        cpu.registers.write(Register::X2, 0x7FFFFFFF);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            0,
            InstructionType::SType,
        );
        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_write(&mut memory).unwrap();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, None);
        assert_eq!(
            memory.read(0x1000, MemAccessSize::Word).unwrap(),
            LoadOp::Op(MemAccessSize::Word, 0x1000, 0x7FFFFFFF),
        );
    }

    #[test]
    fn test_sw_negative_value() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);
        cpu.registers.write(Register::X2, 0x80000000); // -2147483648 in two's complement

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            4,
            InstructionType::SType,
        );
        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_write(&mut memory).unwrap();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, None);
        assert_eq!(
            memory.read(0x1004, MemAccessSize::Word).unwrap(),
            LoadOp::Op(MemAccessSize::Word, 0x1004, 0x80000000),
        );
    }

    #[test]
    fn test_sw_unaligned_address() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1001); // Unaligned address
        cpu.registers.write(Register::X2, 0xABCDEF01);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            0,
            InstructionType::SType,
        );
        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        let result = instruction.memory_write(&mut memory);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MemoryError::UnalignedMemoryWrite(0x1001)
        ));
    }

    #[test]
    fn test_sw_overflow() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, 0xDEADBEEF);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            1,
            InstructionType::SType,
        );
        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        let result = instruction.memory_write(&mut memory);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MemoryError::AddressCalculationOverflow
        ));
    }

    #[test]
    fn test_sw_negative_immediate() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1001);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            0xFFFFFFFF,
            InstructionType::SType,
        );

        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction
            .memory_write(&mut memory)
            .expect("Memory write failed");
    }

    #[test]
    fn test_sw_underflow() {
        let mut cpu = Cpu::default();
        let mut memory = setup_memory();

        cpu.registers.write(Register::X1, 0x01);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SW),
            2,
            1,
            0xFFFFFFFD,
            InstructionType::SType,
        );

        let instruction = SwInstruction::decode(&bare_instruction, &cpu.registers);

        let result = instruction.memory_write(&mut memory);
        assert_eq!(result, Err(MemoryError::AddressCalculationUnderflow));
    }

    // TODO: depending on the memory model, we need to test out of bound memory access
}
