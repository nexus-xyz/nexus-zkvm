use nexus_vm::riscv::BuiltinOpcode;

use super::{BitwiseOp, OR_LOOKUP_IDX};

pub struct Or;
impl BitwiseOp for Or {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::OR;
    const REG2_ACCESSED: bool = true;
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}

pub struct OrI;
impl BitwiseOp for OrI {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ORI;
    const REG2_ACCESSED: bool = false;
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}
