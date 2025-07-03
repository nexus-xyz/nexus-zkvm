use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    BitwiseOp, XOR_LOOKUP_IDX,
};
use crate::components::execution::decoding::{
    type_i::{TypeI, TypeIDecoding},
    type_r::{TypeR, TypeRDecoding},
};

pub struct XorDecoding;
impl TypeRDecoding for XorDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XOR;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Xor = TypeR<XorDecoding>;
impl BitwiseOp for Xor {
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}

pub struct XoriDecoding;
impl TypeIDecoding for XoriDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XORI;
    const C_VAL: Column = Column::CVal;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Xori = TypeI<XoriDecoding>;
impl BitwiseOp for Xori {
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}
