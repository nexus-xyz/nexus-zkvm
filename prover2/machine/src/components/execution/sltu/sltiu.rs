use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SltuOp};
use crate::components::execution::decoding::type_i::{TypeI, TypeIDecoding};

pub struct SltiuDecoding;
impl TypeIDecoding for SltiuDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLTIU;

    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Sltiu = TypeI<SltiuDecoding>;
impl SltuOp for Sltiu {}
