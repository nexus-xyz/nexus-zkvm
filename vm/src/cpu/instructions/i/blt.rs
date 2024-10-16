use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::Instruction,
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct BltInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BltInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <BltInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <BltInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        if (self.rs1 as i32) < (self.rs2 as i32) {
            cpu.pc_mut().branch(self.imm);
        } else {
            cpu.pc_mut().step();
        }

        Some(cpu.pc().value)
    }
}

impl InstructionExecutor for BltInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rs1: registers[ins.op_a],
            rs2: registers[ins.op_b],
            imm: ins.op_c,
        }
    }
}

pub struct BltuInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BltuInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <BltuInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <BltuInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        if self.rs1 < self.rs2 {
            cpu.pc_mut().branch(self.imm);
        } else {
            cpu.pc_mut().step();
        }

        Some(cpu.pc().value)
    }
}

impl InstructionExecutor for BltuInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rs1: registers[ins.op_a],
            rs2: registers[ins.op_b],
            imm: ins.op_c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_blt_branch_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 less than rs2
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLT),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the blt instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated)
        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_blt_branch_not_taken_greater() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 greater than rs2
        cpu.registers.write(Register::X1, 30);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLT),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the blt instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_blt_branch_not_taken_equal() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 equal to rs2
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLT),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the blt instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_blt_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 less than rs2
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLT),
            1,
            2,
            offset,
            InstructionType::BType,
        );

        let mut instruction = BltInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the blt instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated backwards)
        assert_eq!(res, Some(0xF00));
        assert_eq!(cpu.pc.value, 0xF00);
    }

    #[test]
    fn test_blt_signed_comparison() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 to a negative value and rs2 to a positive value
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // -1 in two's complement
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLT),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the blt instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated)
        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bltu_branch_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 less than rs2 (unsigned comparison)
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLTU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltuInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bltu instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated)
        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bltu_branch_not_taken_greater() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 greater than rs2 (unsigned comparison)
        cpu.registers.write(Register::X1, 30);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLTU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltuInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bltu instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_bltu_branch_not_taken_equal() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 equal to rs2
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLTU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltuInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bltu instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_bltu_unsigned_comparison() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 to a large unsigned value and rs2 to a small unsigned value
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // Max unsigned 32-bit value
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLTU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BltuInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bltu instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        // because 0xFFFFFFFF > 1 in unsigned comparison
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_bltu_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set rs1 less than rs2 (unsigned comparison)
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BLTU),
            1,
            2,
            offset,
            InstructionType::BType,
        );

        let mut instruction = BltuInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bltu instruction
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated backwards)
        assert_eq!(res, Some(0xF00));
        assert_eq!(cpu.pc.value, 0xF00);
    }
}
