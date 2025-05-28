use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct AddInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(AddInstruction, |a: u32, b: u32| a.wrapping_add(b));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_add_instruction() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 1, 2);

        let mut instruction = AddInstruction::decode(&bare_instruction, &cpu.registers);
        // Execute the add instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result
        assert_eq!(res, Some(30));
        assert_eq!(cpu.registers.read(Register::X3), 30);
    }

    #[test]
    fn test_add_overflow() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, u32::MAX);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 1, 2);

        let mut instruction = AddInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the add instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (should wrap around to 0)
        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_add_max_intermediate() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x7FFFF000);
        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 1, 0xFFF);

        let mut instruction = AddInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x7FFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0x7FFFFFFF);
    }
}
