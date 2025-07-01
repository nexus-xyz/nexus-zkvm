use nexus_vm::riscv::BuiltinOpcode;

use super::{BitwiseOp, XOR_LOOKUP_IDX};

pub struct Xor;
impl BitwiseOp for Xor {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XOR;
    const REG2_ACCESSED: bool = true;
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}

pub struct XorI;
impl BitwiseOp for XorI {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XORI;
    const REG2_ACCESSED: bool = false;
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}
