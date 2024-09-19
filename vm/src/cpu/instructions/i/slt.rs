use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor},
    },
    error::Result,
    memory::Memory,
    riscv::{Instruction, InstructionType, Register},
};

pub struct SltInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionExecutor for SltInstruction {
    type InstructionState = Self;
    type Result = Result<Option<()>>;

    fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: match ins.ins_type {
                InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                _ => ins.op_c,
            },
        }
    }

    fn memory_read(&mut self, _: &Memory) -> Self::Result {
        Ok(None)
    }

    fn memory_write(&self, _: &mut Memory) -> Self::Result {
        Ok(None)
    }

    fn execute(&mut self) {
        // Perform signed comparison
        self.rd.1 = if (self.rs1 as i32) < (self.rs2 as i32) {
            1
        } else {
            0
        };
    }

    fn write_back(&self, cpu: &mut Cpu) {
        cpu.registers.write(self.rd.0, self.rd.1);
    }
}

pub struct SltuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionExecutor for SltuInstruction {
    type InstructionState = Self;
    type Result = Result<Option<()>>;

    fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: match ins.ins_type {
                InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                _ => ins.op_c,
            },
        }
    }

    fn memory_read(&mut self, _: &Memory) -> Self::Result {
        Ok(None)
    }

    fn memory_write(&self, _: &mut Memory) -> Self::Result {
        Ok(None)
    }

    fn execute(&mut self) {
        self.rd.1 = if self.rs1 < self.rs2 { 1 } else { 0 };
    }

    fn write_back(&self, cpu: &mut Cpu) {
        cpu.registers.write(self.rd.0, self.rd.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::riscv::{InstructionType, Opcode};

    #[test]
    fn test_slt_positive() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(Opcode::SLT, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_slt_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new(Opcode::SLT, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_slt_signed_comparison() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // -1 in two's complement
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(Opcode::SLT, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_sltu_positive() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new(Opcode::SLTU, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_sltu_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new(Opcode::SLTU, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_sltu_unsigned_comparison() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // Maximum unsigned 32-bit value
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new(Opcode::SLTU, 3, 1, 2, InstructionType::RType);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        instruction.write_back(&mut cpu);

        assert_eq!(cpu.registers.read(Register::X3), 0);
    }
}
