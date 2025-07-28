use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SllOp};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct SllDecoding;
impl TypeRDecoding for SllDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLL;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Sll = TypeR<SllDecoding>;
impl SllOp for Sll {}
