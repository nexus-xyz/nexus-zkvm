use nexus_vm::riscv::BuiltinOpcode;

use super::StoreOp;

pub struct Sh;

impl StoreOp for Sh {
    const RAM2_ACCESSED: bool = true;
    const RAM3_4ACCESSED: bool = false;
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SH;
    const ALIGNMENT: u8 = 2;
}
