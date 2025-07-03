use nexus_vm::riscv::BuiltinOpcode;

use super::{AddOp, Column, PreprocessedColumn};
use crate::components::execution::decoding::type_r::{TypeR, TypeRDecoding};

pub struct AddDecoding;
impl TypeRDecoding for AddDecoding {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::ADD;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

pub type Add = TypeR<AddDecoding>;
impl AddOp for Add {}
