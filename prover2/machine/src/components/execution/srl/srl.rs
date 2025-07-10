use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SrlOp};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct SrlDecoding;
impl TypeRDecoding for SrlDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SRL;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Srl = TypeR<SrlDecoding>;
impl SrlOp for Srl {}
