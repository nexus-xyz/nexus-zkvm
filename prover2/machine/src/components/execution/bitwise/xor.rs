use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    XOR_LOOKUP_IDX,
};
use crate::components::execution::{
    bitwise::{type_i::TypeIBitwiseDecoding, type_r::TypeRBitwiseDecoding},
    decoding::{
        type_i::{TypeI, TypeIDecoding},
        type_r::{TypeR, TypeRDecoding},
    },
};

pub struct XorDecoding;
impl TypeRDecoding for XorDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XOR;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeRBitwiseDecoding for XorDecoding {
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}
pub type Xor = TypeR<XorDecoding>;

pub struct XoriDecoding;
impl TypeIDecoding for XoriDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::XORI;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeIBitwiseDecoding for XoriDecoding {
    const BITWISE_LOOKUP_IDX: u32 = XOR_LOOKUP_IDX;
}
pub type Xori = TypeI<XoriDecoding>;
