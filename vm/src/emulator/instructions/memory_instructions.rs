use super::macros::{define_execute_LOAD_instruction, define_execute_STORE_instruction};
use crate::{
    cpu::{instructions, Cpu, InstructionExecutor},
    error::Result,
    memory::Memory,
    riscv::Instruction,
};

define_execute_LOAD_instruction!(execute_lb, instructions::LbInstruction);
define_execute_LOAD_instruction!(execute_lbu, instructions::LbuInstruction);
define_execute_LOAD_instruction!(execute_lh, instructions::LhInstruction);
define_execute_LOAD_instruction!(execute_lhu, instructions::LhuInstruction);
define_execute_LOAD_instruction!(execute_lw, instructions::LwInstruction);

define_execute_STORE_instruction!(execute_sb, instructions::SbInstruction);
define_execute_STORE_instruction!(execute_sh, instructions::ShInstruction);
define_execute_STORE_instruction!(execute_sw, instructions::SwInstruction);
