use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor, InstructionState},
    },
    error::Result,
    memory::MemoryProcessor,
    riscv::Instruction,
};

pub struct BneInstruction {
    rs1: u32,
    rs2: u32,
    imm: u32,
}

impl InstructionState for BneInstruction {
    type Result = Option<u32>;

    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<Self::Result> {
        Ok(None)
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<Self::Result> {
        Ok(None)
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut Cpu) {
        if self.rs1 != self.rs2 {
            cpu.pc.branch(self.imm);
        } else {
            cpu.pc.step();
        }
    }
}

impl InstructionExecutor for BneInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
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
    fn test_bne_branch_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set different values in registers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BNE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BneInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bne instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated)
        assert_eq!(cpu.pc, 0x1100);
    }

    #[test]
    fn test_bne_branch_not_taken() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set equal values in registers
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BNE),
            1,
            2,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BneInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bne instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(cpu.pc, 0x1004);
    }

    #[test]
    fn test_bne_zero_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set different values in registers
        cpu.registers.write(Register::X1, 5);
        cpu.registers.write(Register::X2, 6);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BNE),
            1,
            2,
            0,
            InstructionType::BType,
        );

        let mut instruction = BneInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bne instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check if branch was taken but PC didn't change due to zero offset
        assert_eq!(cpu.pc, 0x1000);
    }

    #[test]
    fn test_bne_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set different values in registers
        cpu.registers.write(Register::X1, 15);
        cpu.registers.write(Register::X2, 16);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BNE),
            1,
            2,
            offset,
            InstructionType::BType,
        );

        let mut instruction = BneInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bne instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check if branch was taken (PC should be updated backwards)
        assert_eq!(cpu.pc, 0xF00);
    }

    #[test]
    fn test_bne_same_register() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set a value in a register
        cpu.registers.write(Register::X1, 25);

        let bare_instruction = Instruction::new(
            Opcode::from(BuiltinOpcode::BNE),
            1,
            1,
            0x100,
            InstructionType::BType,
        );

        let mut instruction = BneInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the bne instruction
        instruction.execute();
        instruction.write_back(&mut cpu);

        // Check if branch was not taken (PC should step)
        assert_eq!(cpu.pc, 0x1004);
    }
}
