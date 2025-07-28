use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SllOp};
use crate::components::execution::decoding::type_i_shamt::{TypeIShamt, TypeIShamtDecoding};

pub struct SlliDecoding;
impl TypeIShamtDecoding for SlliDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLLI;

    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Slli = TypeIShamt<SlliDecoding>;
impl SllOp for Slli {}
