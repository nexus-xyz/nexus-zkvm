pub mod encoder;
pub mod instruction;
pub mod opcode;
pub mod register;

pub use encoder::encode_instruction;
pub use opcode::Opcode;
