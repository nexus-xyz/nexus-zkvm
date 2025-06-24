use nexus_vm::riscv::BuiltinOpcode;

use super::StoreOp;

pub struct Sb;

impl StoreOp for Sb {
    const RAM2_ACCESSED: bool = false;
    const RAM3_4ACCESSED: bool = false;
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SB;
    const ALIGNMENT: u8 = 0;
}
