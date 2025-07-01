use nexus_vm::riscv::BuiltinOpcode;

use super::{BitwiseOp, AND_LOOKUP_IDX};

pub struct And;
impl BitwiseOp for And {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::AND;
    const REG2_ACCESSED: bool = true;
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}

pub struct AndI;
impl BitwiseOp for AndI {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ANDI;
    const REG2_ACCESSED: bool = false;
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}
