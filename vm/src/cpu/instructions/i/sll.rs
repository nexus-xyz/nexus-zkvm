use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct SllInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(SllInstruction, |a: u32, b: u32| a << (b & 0x1F));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_sll_basic() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0b1);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SLL),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = SllInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the sll instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (1 << 3 = 8)
        assert_eq!(res, Some(0b1000));
        assert_eq!(cpu.registers.read(Register::X3), 0b1000);
    }

    #[test]
    fn test_sll_zero_shift() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x1FFFFFFF);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SLL),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = SllInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting by 0 should not change the value
        assert_eq!(res, Some(0x1FFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0x1FFFFFFF);
    }

    #[test]
    fn test_sll_overflow() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x80000000);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SLL),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = SllInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting the highest bit should result in 0
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_sll_large_shift() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 1);
        cpu.registers.write(Register::X2, 31);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SLL),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = SllInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting 1 by 31 should result in 0x80000000
        assert_eq!(res, Some(0x80000000));
        assert_eq!(cpu.registers.read(Register::X3), 0x80000000);
    }

    #[test]
    fn test_sll_shift_by_more_than_31() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 1);
        cpu.registers.write(Register::X2, 32);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::SLL),
            3,
            1,
            2,
            InstructionType::RType,
        );

        let mut instruction = SllInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting by 32 or more should be equivalent to shifting by the amount modulo 32
        // In this case, it's equivalent to not shifting at all
        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }
}
