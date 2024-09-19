use crate::{
    cpu::{instructions, Cpu, InstructionExecutor},
    error::Result,
    memory::Memory,
    riscv::Instruction,
};

use super::macros::define_execute_ALU_instruction;

define_execute_ALU_instruction!(execute_add, instructions::AddInstruction);
define_execute_ALU_instruction!(execute_and, instructions::AndInstruction);
define_execute_ALU_instruction!(execute_or, instructions::OrInstruction);
define_execute_ALU_instruction!(execute_sll, instructions::SllInstruction);
define_execute_ALU_instruction!(execute_srl, instructions::SrlInstruction);
define_execute_ALU_instruction!(execute_sra, instructions::SraInstruction);
define_execute_ALU_instruction!(execute_sub, instructions::SubInstruction);
define_execute_ALU_instruction!(execute_xor, instructions::XorInstruction);
define_execute_ALU_instruction!(execute_slt, instructions::SltInstruction);
define_execute_ALU_instruction!(execute_sltu, instructions::SltuInstruction);
define_execute_ALU_instruction!(execute_div, instructions::DivInstruction);
define_execute_ALU_instruction!(execute_divu, instructions::DivuInstruction);
define_execute_ALU_instruction!(execute_mul, instructions::MulInstruction);
define_execute_ALU_instruction!(execute_mulhu, instructions::MulhuInstruction);
define_execute_ALU_instruction!(execute_mulh, instructions::MulhInstruction);
define_execute_ALU_instruction!(execute_mulhsu, instructions::MulhsuInstruction);
define_execute_ALU_instruction!(execute_rem, instructions::RemInstruction);
define_execute_ALU_instruction!(execute_remu, instructions::RemuInstruction);
