use nexus_vm::riscv::BuiltinOpcode;

use super::{
    columns::{Column, PreprocessedColumn},
    AND_LOOKUP_IDX,
};
use crate::components::execution::{
    bitwise::{type_i::TypeIBitwiseDecoding, type_r::TypeRBitwiseDecoding},
    decoding::{
        type_i::{TypeI, TypeIDecoding},
        type_r::{TypeR, TypeRDecoding},
    },
};

pub struct AndDecoding;
impl TypeRDecoding for AndDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::AND;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeRBitwiseDecoding for AndDecoding {
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}
pub type And = TypeR<AndDecoding>;

pub struct AndiDecoding;
impl TypeIDecoding for AndiDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ANDI;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

impl TypeIBitwiseDecoding for AndiDecoding {
    const BITWISE_LOOKUP_IDX: u32 = AND_LOOKUP_IDX;
}
pub type Andi = TypeI<AndiDecoding>;
