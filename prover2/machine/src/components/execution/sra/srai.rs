use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SraOp};
use crate::components::execution::decoding::type_i_shamt::{TypeIShamt, TypeIShamtDecoding};

pub struct SraiDecoding;
impl TypeIShamtDecoding for SraiDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SRAI;

    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Srai = TypeIShamt<SraiDecoding>;
impl SraOp for Srai {}
