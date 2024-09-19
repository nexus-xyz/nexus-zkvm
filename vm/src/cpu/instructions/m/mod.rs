// RV32M Multiply extension
mod mul;
// Includes MULH, MULHU and MULHSU
mod mulh;
// Includes DIV and DIVU
mod div;
// Includes REM and REMU
mod rem;

pub use div::{DivInstruction, DivuInstruction};
pub use mul::MulInstruction;
pub use mulh::{MulhInstruction, MulhsuInstruction, MulhuInstruction};
pub use rem::{RemInstruction, RemuInstruction};
