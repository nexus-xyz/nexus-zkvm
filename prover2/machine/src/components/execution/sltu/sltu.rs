use nexus_vm::riscv::BuiltinOpcode;

use super::{Column, PreprocessedColumn, SltuOp};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct SltuDecoding;
impl TypeRDecoding for SltuDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SLTU;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Sltu = TypeR<SltuDecoding>;
impl SltuOp for Sltu {}
