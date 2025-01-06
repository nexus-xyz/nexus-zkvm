use crate::{
    cpu::state::{InstructionExecutor, InstructionState},
    memory::{LoadOps, MemoryProcessor, StoreOps},
    riscv::{Instruction, InstructionType, Register},
};
use nexus_common::{
    cpu::{Processor, Registers},
    error::MemoryError,
};

pub struct SltInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionState for SltInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <SltInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <SltInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {
        // Perform signed comparison
        self.rd.1 = if (self.rs1 as i32) < (self.rs2 as i32) {
            1
        } else {
            0
        };
    }

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        cpu.registers_mut().write(self.rd.0, self.rd.1);
        Some(self.rd.1)
    }
}

impl InstructionExecutor for SltInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: match ins.ins_type {
                InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                _ => ins.op_c,
            },
        }
    }
}

pub struct SltuInstruction {
    rd: (Register, u32),
    rs1: u32,
    rs2: u32,
}

impl InstructionState for SltuInstruction {
    fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<LoadOps, MemoryError> {
        <SltuInstruction as InstructionState>::readless()
    }

    fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<StoreOps, MemoryError> {
        <SltuInstruction as InstructionState>::writeless()
    }

    fn execute(&mut self) {
        self.rd.1 = if self.rs1 < self.rs2 { 1 } else { 0 };
    }

    fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
        cpu.registers_mut().write(self.rd.0, self.rd.1);
        Some(self.rd.1)
    }
}

impl InstructionExecutor for SltuInstruction {
    type InstructionState = Self;

    fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: registers[ins.op_b],
            rs2: match ins.ins_type {
                InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                _ => ins.op_c,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cpu::Cpu,
        riscv::{BuiltinOpcode, Opcode},
    };

    #[test]
    fn test_slt_positive() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 3, 1, 2);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_slt_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 3, 1, 2);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_slt_signed_comparison() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // -1 in two's complement
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 3, 1, 2);
        let mut instruction = SltInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_sltu_positive() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 10);
        cpu.registers.write(Register::X2, 20);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 3, 1, 2);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(1));
        assert_eq!(cpu.registers.read(Register::X3), 1);
    }

    #[test]
    fn test_sltu_negative() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 20);
        cpu.registers.write(Register::X2, 10);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 3, 1, 2);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }

    #[test]
    fn test_sltu_unsigned_comparison() {
        let mut cpu = Cpu::default();
        cpu.registers.write(Register::X1, 0xFFFFFFFF); // Maximum unsigned 32-bit value
        cpu.registers.write(Register::X2, 1);

        let bare_instruction = Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 3, 1, 2);
        let mut instruction = SltuInstruction::decode(&bare_instruction, &cpu.registers);

        instruction.execute();
        let res = instruction.write_back(&mut cpu);

        assert_eq!(res, Some(0));
        assert_eq!(cpu.registers.read(Register::X3), 0);
    }
}
