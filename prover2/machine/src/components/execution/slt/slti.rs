use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SltOp};
use crate::components::execution::decoding::type_i::{TypeI, TypeIDecoding};

pub struct SltiDecoding;
impl TypeIDecoding for SltiDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLTI;
    const C_VAL: Column = Column::CVal;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Slti = TypeI<SltiDecoding>;
impl SltOp for Slti {}
