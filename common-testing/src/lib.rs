pub mod emulator;

use nexus_vm::riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode};

pub fn program_trace(log_size: u32) -> Vec<BasicBlock> {
    let mut i = 0u8;
    let mut j = 1u8;
    let mut k = 2u8;

    let insts = std::iter::once(Instruction::new_ir(
        Opcode::from(BuiltinOpcode::ADDI),
        1,
        0,
        1,
    ))
    .chain(std::iter::from_fn(|| {
        let inst = Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), k, j, i.into());
        const NUM_REGISTERS: u8 = {
            assert!(nexus_common::constants::NUM_REGISTERS <= u8::MAX as u32);
            nexus_common::constants::NUM_REGISTERS as u8
        };
        i = (i + 1) % NUM_REGISTERS;
        j = (j + 1) % NUM_REGISTERS;
        k = (k + 1) % NUM_REGISTERS;
        Some(inst)
    }))
    .take(2usize.pow(log_size))
    .collect();
    vec![BasicBlock::new(insts)]
}
