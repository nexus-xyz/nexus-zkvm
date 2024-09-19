use crate::{
    cpu::{
        registerfile::RegisterFile,
        state::{Cpu, InstructionExecutor},
    },
    error::Result,
    memory::Memory,
    riscv::{Instruction, InstructionType, Register},
};

#[allow(dead_code)]
pub struct CustomInstruction {
    rd: (Register, u32),
    rs1: (Register, u32),
    rs2: (Option<Register>, u32),
}

impl InstructionExecutor for CustomInstruction {
    type InstructionState = CustomInstruction;
    type Result = Result<()>;

    fn decode(ins: &Instruction, registers: &RegisterFile) -> Self::InstructionState {
        Self {
            rd: (ins.op_a, registers[ins.op_a]),
            rs1: (ins.op_b, registers[ins.op_b]),
            rs2: match ins.ins_type {
                InstructionType::RType => (
                    Some(Register::from(ins.op_c as u8)),
                    registers[Register::from(ins.op_c as u8)],
                ),
                _ => (None, ins.op_c),
            },
        }
    }

    fn memory_read(&mut self, _memory: &Memory) -> Self::Result {
        Ok(())
    }

    fn execute(&mut self) {}

    fn memory_write(&self, _memory: &mut Memory) -> Self::Result {
        Ok(())
    }

    fn write_back(&self, _cpu: &mut Cpu) {}
}
