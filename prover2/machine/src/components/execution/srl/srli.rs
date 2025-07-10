use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SrlOp};
use crate::components::execution::decoding::type_i_shamt::{TypeIShamt, TypeIShamtDecoding};

pub struct SrliDecoding;
impl TypeIShamtDecoding for SrliDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SRLI;
    const C_VAL: Column = Column::CVal;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Srli = TypeIShamt<SrliDecoding>;
impl SrlOp for Srli {}
