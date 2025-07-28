use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    OR_LOOKUP_IDX,
};
use crate::components::execution::{
    bitwise::{type_i::TypeIBitwiseDecoding, type_r::TypeRBitwiseDecoding},
    decoding::{
        type_i::{TypeI, TypeIDecoding},
        type_r::{TypeR, TypeRDecoding},
    },
};

pub struct OrDecoding;
impl TypeRDecoding for OrDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::OR;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeRBitwiseDecoding for OrDecoding {
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}
pub type Or = TypeR<OrDecoding>;

pub struct OriDecoding;
impl TypeIDecoding for OriDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ORI;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeIBitwiseDecoding for OriDecoding {
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}
pub type Ori = TypeI<OriDecoding>;
