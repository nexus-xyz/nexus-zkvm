use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::Instruction,
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct BgeInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BgeInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <BgeInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <BgeInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        if (self.rs1 as i32) >= (self.rs2 as i32) {
            cpu.pc_mut().branch(self.imm);
        } else {
            cpu.pc_mut().step();
        }

        Some(cpu.pc().value)
    }
}

impl InstructionExecutor for BgeInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rs1: registers[ins.op_a],
            rs2: registers[ins.op_b],
            imm: ins.op_c,
        }
    }
}

pub struct BgeuInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BgeuInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <BgeuInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <BgeuInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        if self.rs1 >= self.rs2 {
            cpu.pc_mut().branch(self.imm);
        } else {
            cpu.pc_mut().step();
        }

        Some(cpu.pc().value)
    }
}

impl InstructionExecutor for BgeuInstruction {
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
    fn test_bge_branch_taken_greater() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bge_branch_taken_equal() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bge_branch_not_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_bge_signed_comparison() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 0xFFFFFFFF); // -1 in two's complement
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004); // Branch not taken because -1 < 1
    }

    // Tests for BgeuInstruction
    #[test]
    fn test_bgeu_branch_taken_greater() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGEU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bgeu_branch_taken_equal() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGEU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100);
    }

    #[test]
    fn test_bgeu_branch_not_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGEU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(res, Some(0x1004));
        assert_eq!(cpu.pc.value, 0x1004);
    }

    #[test]
    fn test_bgeu_unsigned_comparison() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 0xFFFFFFFF); // Max unsigned 32-bit value
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGEU),
            1,
            2,
            0x100,
            InstructionType::BType,
        );
        let mut instruction = BgeuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0x1100));
        assert_eq!(cpu.pc.value, 0x1100); // Branch taken because 0xFFFFFFFF > 1 in unsigned comparison
    }

    #[test]
    fn test_bge_bgeu_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);

        // Test BGE
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGE),
            1,
            2,
            offset,
            InstructionType::BType,
        );
        let mut instruction = BgeInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0xF00));
        assert_eq!(cpu.pc.value, 0xF00);

        // Reset PC
        cpu.pc.value = 0x1000;

        // Test BGEU
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BGEU),
            1,
            2,
            offset,
            InstructionType::BType,
        );
        let mut instruction = BgeuInstruction::decode(&bare_instruction, &cpu.registers);
        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0xF00));
        assert_eq!(cpu.pc.value, 0xF00);
    }
}
