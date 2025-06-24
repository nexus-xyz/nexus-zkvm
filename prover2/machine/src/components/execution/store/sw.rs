use nexus_vm::riscv::BuiltinOpcode;

use super::StoreOp;

pub struct Sw;

impl StoreOp for Sw {
    const RAM2_ACCESSED: bool = true;
    const RAM3_4ACCESSED: bool = true;
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SW;
    const ALIGNMENT: u8 = 4;
}
