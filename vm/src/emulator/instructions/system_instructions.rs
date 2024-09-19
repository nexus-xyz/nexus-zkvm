use crate::{
    cpu::{instructions, Cpu, InstructionExecutor},
    error::{Result, VMError},
    memory::Memory,
    riscv::Instruction,
};

pub fn execute_lui(
    cpu: &mut Cpu,
    _data_memory: &mut Memory,
    instruction: &Instruction,
) -> Result<()> {
    let instruction = instructions::LuiInstruction::decode(instruction, &cpu.registers);
    instruction.write_back(cpu);
    Ok(())
}

pub fn executable_auipc(
    cpu: &mut Cpu,
    _data_memory: &mut Memory,
    instruction: &Instruction,
) -> Result<()> {
    let instruction = instructions::AuipcInstruction::decode(instruction, &cpu.registers);
    instruction.write_back(cpu);
    Ok(())
}

pub fn execute_nop(
    _cpu: &mut Cpu,
    _data_memory: &mut Memory,
    _instruction: &Instruction,
) -> Result<()> {
    Ok(())
}

pub fn execute_ecall(
    _cpu: &mut Cpu,
    _data_memory: &mut Memory,
    _instruction: &Instruction,
) -> Result<()> {
    // TODO: implement syscall.rs
    Ok(())
}

pub fn execute_unimplemented(
    cpu: &mut Cpu,
    _data_memory: &mut Memory,
    _instruction: &Instruction,
) -> Result<()> {
    Err(VMError::UnimplementedInstruction(cpu.pc.value))
}
