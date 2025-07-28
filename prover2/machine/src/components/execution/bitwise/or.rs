use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    BitwiseOp, OR_LOOKUP_IDX,
};
use crate::components::execution::decoding::{
    type_i::{TypeI, TypeIDecoding},
    type_r::{TypeR, TypeRDecoding},
};

pub struct OrDecoding;
impl TypeRDecoding for OrDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::OR;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Or = TypeR<OrDecoding>;
impl BitwiseOp for Or {
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}

pub struct OriDecoding;
impl TypeIDecoding for OriDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ORI;
    const C_VAL: Column = Column::CVal;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Ori = TypeI<OriDecoding>;
impl BitwiseOp for Ori {
    const BITWISE_LOOKUP_IDX: u32 = OR_LOOKUP_IDX;
}
