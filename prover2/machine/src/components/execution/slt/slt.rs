use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SltOp};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct SltDecoding;
impl TypeRDecoding for SltDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLT;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Slt = TypeR<SltDecoding>;
impl SltOp for Slt {}
