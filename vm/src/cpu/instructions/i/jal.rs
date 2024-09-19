use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor},
    },
    error::Result,
    memory::Memory,
    riscv::{Instruction, Register},
};

pub struct JalInstruction {
    rd: Register,
    imm: u32,
}

impl InstructionExecutor for JalInstruction {
    type InstructionState = Self;
    type Result = Result<Option<u32>>;

    fn decode(ins: &Instruction, _: &RegisterFile) -> Self {
        Self {
            rd: ins.op_a,
            imm: ins.op_c,
        }
    }

    fn memory_read(&mut self, _: &Memory) -> Self::Result {
        Ok(None)
    }

    fn memory_write(&self, _: &mut Memory) -> Self::Result {
        Ok(None)
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut Cpu) {
        cpu.registers.write(self.rd, cpu.pc.value + 4);
        cpu.pc.jal(self.imm);
    }
}

pub struct JalrInstruction {
    rd: Register,
    rs1: u32,
    imm: u32,
}

impl InstructionExecutor for JalrInstruction {
    type InstructionState = Self;
    type Result = Result<Option<u32>>;

    fn decode(ins: &Instruction, register: &RegisterFile) -> Self {
        Self {
            rd: ins.op_a,
            rs1: register[ins.op_b],
            imm: ins.op_c,
        }
    }

    fn memory_read(&mut self, _: &Memory) -> Self::Result {
        Ok(None)
    }

    fn memory_write(&self, _: &mut Memory) -> Self::Result {
        Ok(None)
    }

    fn execute(&mut self) {}

    fn write_back(&self, cpu: &mut Cpu) {
        let tmp = cpu.pc.value;
        cpu.pc.jalr(self.rs1, self.imm);
        cpu.registers.write(self.rd, tmp + 4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::state::Cpu;
    use crate::riscv::{Instruction, InstructionType, Opcode, Register};

    #[test]
    fn test_jal_positive_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use a positive offset (0x100)
        let offset = 0x100;
        let bare_instruction = Instruction::new(Opcode::JAL, 1, 0, offset, InstructionType::JType);
        let instruction = JalInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jal instruction
        instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated forwards)
        assert_eq!(cpu.pc.value, 0x1100);

        // Check if the link address was stored correctly
        assert_eq!(cpu.registers.read(Register::X1), 0x1004);
    }

    #[test]
    fn test_jal_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new(Opcode::JAL, 2, 0, offset, InstructionType::JType);
        let instruction = JalInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jal instruction
        instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated backwards)
        assert_eq!(cpu.pc.value, 0xF00);

        // Check if the link address was stored correctly
        assert_eq!(cpu.registers.read(Register::X2), 0x1004);
    }

    #[test]
    fn test_jalr_positive_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set base address in rs1
        cpu.registers.write(Register::X1, 0x2000);

        // Use a positive offset (0x100)
        let offset = 0x100;
        let bare_instruction = Instruction::new(Opcode::JALR, 2, 1, offset, InstructionType::IType);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to rs1 + offset)
        assert_eq!(cpu.pc.value, 0x2100);

        // Check if the link address was stored correctly
        assert_eq!(cpu.registers.read(Register::X2), 0x1004);
    }

    #[test]
    fn test_jalr_negative_offset() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Set base address in rs1
        cpu.registers.write(Register::X1, 0x2000);

        // Use a negative offset (-0x100)
        let offset = (!256u32).wrapping_add(1);
        let bare_instruction = Instruction::new(Opcode::JALR, 3, 1, offset, InstructionType::IType);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to rs1 + offset)
        assert_eq!(cpu.pc.value, 0x1F00);

        // Check if the link address was stored correctly
        assert_eq!(cpu.registers.read(Register::X3), 0x1004);
    }

    #[test]
    fn test_jalr_zero_register() {
        let mut cpu = Cpu::default();
        cpu.pc.value = 0x1000;

        // Use x0 as rs1 (should always be 0)
        let offset = 0x100;
        let bare_instruction = Instruction::new(Opcode::JALR, 4, 0, offset, InstructionType::IType);
        let instruction = JalrInstruction::decode(&bare_instruction, &cpu.registers);

        // Execute the jalr instruction
        instruction.write_back(&mut cpu);

        // Check if jump was taken (PC should be updated to offset only, since x0 is always 0)
        assert_eq!(cpu.pc.value, 0x100);

        // Check if the link address was stored correctly
        assert_eq!(cpu.registers.read(Register::X4), 0x1004);
    }
}
