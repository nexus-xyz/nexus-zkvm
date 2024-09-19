use crate::{
    cpu::{instructions, Cpu, InstructionExecutor},
    error::Result,
    memory::Memory,
    riscv::Instruction,
};

use super::macros::define_execute_BRANCH_instruction;

define_execute_BRANCH_instruction!(execute_beq, instructions::BeqInstruction);
define_execute_BRANCH_instruction!(execute_bne, instructions::BneInstruction);
define_execute_BRANCH_instruction!(execute_blt, instructions::BltInstruction);
define_execute_BRANCH_instruction!(execute_bltu, instructions::BltuInstruction);
define_execute_BRANCH_instruction!(execute_bge, instructions::BgeInstruction);
define_execute_BRANCH_instruction!(execute_bgeu, instructions::BgeuInstruction);
define_execute_BRANCH_instruction!(execute_jal, instructions::JalInstruction);
define_execute_BRANCH_instruction!(execute_jalr, instructions::JalrInstruction);
