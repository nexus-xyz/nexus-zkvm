use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct OrInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(OrInstruction, |a: u32, b: u32| a | b);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_or_instruction() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0b1010);
        cpu.registers.write(Register::X2, 0b1100);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 3, 1, 2);

        let mut instruction = OrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the or instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (1010 | 1100 = 1110)
        assert_eq!(res, Some(0b1110));
        assert_eq!(cpu.registers.read(Register::X3), 0b1110);
    }

    #[test]
    fn test_or_with_zero() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0xABCDEF12);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 3, 1, 2);

        let mut instruction = OrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the or instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (anything OR 0 should be itself)
        assert_eq!(res, Some(0xABCDEF12));
        assert_eq!(cpu.registers.read(Register::X3), 0xABCDEF12);
    }

    #[test]
    fn test_or_with_all_ones() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0xABCDEF12);
        cpu.registers.write(Register::X2, 0xFFFFFFFF);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 3, 1, 2);

        let mut instruction = OrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the or instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (anything OR all 1's should be all 1's)
        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }

    #[test]
    fn test_or_same_register() {
        let mut cpu = Cpu::default();

        // Set initial register value
        cpu.registers.write(Register::X1, 0xAA55AA55);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 1, 1, 1);

        let mut instruction = OrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the or instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (OR with itself should be itself)
        assert_eq!(res, Some(0xAA55AA55));
        assert_eq!(cpu.registers.read(Register::X1), 0xAA55AA55);
    }

    #[test]
    fn test_or_complementary_values() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0xAAAAAAAA);
        cpu.registers.write(Register::X2, 0x55555555);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 3, 1, 2);

        let mut instruction = OrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the or instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (complementary values should result in all 1's)
        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }
}
