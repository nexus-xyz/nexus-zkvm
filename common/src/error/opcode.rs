use thiserror::Error;

use crate::riscv::Opcode;

#[derive(Debug, Error, PartialEq)]
pub enum OpcodeError {
    #[error("Cannot convert non-builtin opcode to BuiltinOpcode: {0}")]
    OpcodeNotBuiltin(Opcode),
}
