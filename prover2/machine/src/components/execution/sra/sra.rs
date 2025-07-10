use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SraOp};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct SraDecoding;
impl TypeRDecoding for SraDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SRA;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Sra = TypeR<SraDecoding>;
impl SraOp for Sra {}
