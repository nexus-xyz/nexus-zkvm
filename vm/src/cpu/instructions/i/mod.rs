// RV32I Base Integer Instructions

// Arithmetic and Logical Instructions
mod add;
mod and;
mod or;
mod sll;
mod sra;
mod srl;
mod sub;
mod xor;
// Includes SLT and SLTU
mod slt;

// Load Instructions
mod sb;
mod sh;
mod sw;

// Store Instructions
// Includes LB and LBU
mod lb;
// Includes LH and LHU
mod lh;
mod lw;

// Branch Instructions
mod beq;
mod bne;
// Includes BLT and BLTU
mod blt;
// Include BGE and BGEU
mod bge;

// Jump Instructions
// Includes JAL and JALR
mod jal;

// LUI and AUIPC
mod auipc;
mod lui;

pub use add::AddInstruction;
pub use and::AndInstruction;
pub use or::OrInstruction;
pub use sll::SllInstruction;
pub use slt::{SltInstruction, SltuInstruction};
pub use sra::SraInstruction;
pub use srl::SrlInstruction;
pub use sub::SubInstruction;
pub use xor::XorInstruction;

pub use sb::SbInstruction;
pub use sh::ShInstruction;
pub use sw::SwInstruction;

pub use lb::{LbInstruction, LbuInstruction};
pub use lh::{LhInstruction, LhuInstruction};
pub use lw::LwInstruction;

pub use beq::BeqInstruction;
pub use bge::{BgeInstruction, BgeuInstruction};
pub use blt::{BltInstruction, BltuInstruction};
pub use bne::BneInstruction;

pub use jal::{JalInstruction, JalrInstruction};

pub use auipc::AuipcInstruction;
pub use lui::LuiInstruction;
