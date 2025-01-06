use crate::cpu::instructions::macros::implement_arithmetic_executor;
use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::cpu::{Processor, Registers};

pub struct SrlInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

implement_arithmetic_executor!(SrlInstruction, |a: u32, b: u32| a >> (b & 0x1F));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, Opcode, Register};

    #[test]
    fn test_srl_basic() {
        let mut cpu = Cpu::default();

        // Set initial register values
        cpu.registers.write(Register::X1, 0b1000);
        cpu.registers.write(Register::X2, 3);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the srl instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check the result (1000 >> 3 = 1)
        assert_eq!(res, Some(0b1));
        assert_eq!(cpu.registers.read(Register::X3), 0b1);
    }

    #[test]
    fn test_srl_zero_shift() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 0);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting by 0 should not change the value
        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }

    #[test]
    fn test_srl_all_bits() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting all 1's right by 1 should result in 0x7FFFFFFF
        assert_eq!(res, Some(0x7FFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0x7FFFFFFF);
    }

    #[test]
    fn test_srl_large_shift() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x80000000);
        cpu.registers.write(Register::X2, 31);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting 0x80000000 right by 31 should result in 1
        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_srl_shift_by_more_than_31() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0xFFFFFFFF);
        cpu.registers.write(Register::X2, 32);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting by 32 or more should be equivalent to shifting by the amount modulo 32
        // In this case, it's equivalent to not shifting at all
        assert_eq!(res, Some(0xFFFFFFFF));
        assert_eq!(cpu.registers.read(Register::X3), 0xFFFFFFFF);
    }

    #[test]
    fn test_srl_sign_bit() {
        let mut cpu = Cpu::default();

        cpu.registers.write(Register::X1, 0x80000000);
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2);

        let mut instruction = SrlInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Shifting right should not preserve the sign bit
        assert_eq!(res, Some(0x40000000));
        assert_eq!(cpu.registers.read(Register::X3), 0x40000000);
    }
}
