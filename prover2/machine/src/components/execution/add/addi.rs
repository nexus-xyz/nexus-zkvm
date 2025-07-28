use nexus_vm::riscv::BuiltinOpcode;

use super::{AddOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_i::{TypeI, TypeIDecoding};

pub struct AddiDecoding;
impl TypeIDecoding for AddiDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ADDI;
    const IS_LOCAL_PAD: Column = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Addi = TypeI<AddiDecoding>;
impl AddOp for Addi {}
