use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    BitwiseOp, AND_LOOKUP_IDX,
};
use crate::components::execution::decoding::{
    type_i::{TypeI, TypeIDecoding},
    type_r::{TypeR, TypeRDecoding},
};

pub struct AndDecoding;
impl TypeRDecoding for AndDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::AND;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type And = TypeR<AndDecoding>;
impl BitwiseOp for And {
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}

pub struct AndiDecoding;
impl TypeIDecoding for AndiDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ANDI;
    const C_VAL: Column = Column::CVal;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Andi = TypeI<AndiDecoding>;
impl BitwiseOp for Andi {
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}
