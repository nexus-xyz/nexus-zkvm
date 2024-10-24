use crate::{
    cpu::{
        instructions::macros::implement_load_instruction,
        state::{InstructionExecutor, InstructionState},
    },
    memory::{LoadOp, LoadOps, MemAccessSize, MemoryProcessor, StoreOps},
    riscv::{Instruction, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct LwInstruction {
    rd: (Register, u32),
    rs1: u32,
    imm: u32,
}

implement_load_instruction!(LwInstruction, MemAccessSize::Word, false, u32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::memory::{VariableMemory, RW};
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};
    use nexus_common::error::MemoryError;

    fn setup_memory() -> VariableMemory<RW> {
        let mut memory = VariableMemory::<RW>::default();
        // Set up some test values in memory
        memory
            .write(0x1000, MemAccessSize::Word, 0xFFFFFFFF)
            .unwrap();
        memory
            .write(0x100C, MemAccessSize::Word, 0x00000000)
            .unwrap();
        memory
    }

    #[test]
    fn test_lw_max_value() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LW),
            2,
            1,
            0,
            InstructionType::IType,
        );
        let mut instruction = LwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X2), 0xFFFFFFFF);
    }

    #[test]
    fn test_lw_zero() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1000);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LW),
            2,
            1,
            12,
            InstructionType::IType,
        );
        let mut instruction = LwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.memory_read(&memory).unwrap();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x00000000));
        assert_eq!(cpu.registers.read(Register::X2), 0x00000000);
    }

    #[test]
    fn test_lw_address_overflow() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, u32::MAX);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LW),
            2,
            1,
            1,
            InstructionType::IType,
        );
        let mut instruction = LwInstruction::decode(&bare_instruction, &cpu.registers);

        assert!(instruction.memory_read(&memory).is_err());
    }

    #[test]
    fn test_lw_negative_immediate() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x1001);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LW),
            2,
            1,
            0xFFFFFFFF,
            InstructionType::IType,
        );

        let mut instruction = LwInstruction::decode(&bare_instruction, &cpu.registers);

        instruction
            .memory_read(&memory)
            .expect("Memory read failed");
    }

    #[test]
    fn test_lw_underflow() {
        let mut cpu = Cpu::default();
        let memory = setup_memory();

        cpu.registers.write(Register::X1, 0x01);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::LW),
            2,
            1,
            0xFFFFFFFD,
            InstructionType::IType,
        );

        let mut instruction = LwInstruction::decode(&bare_instruction, &cpu.registers);

        let result = instruction.memory_read(&memory);
        assert_eq!(result, Err(MemoryError::AddressCalculationUnderflow));
    }
}
