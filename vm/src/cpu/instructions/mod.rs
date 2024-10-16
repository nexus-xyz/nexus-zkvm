// RV32I Base Integer Instructions
mod i;
pub use i::{
    AddInstruction, AndInstruction, AuipcInstruction, BeqInstruction, BgeInstruction,
    BgeuInstruction, BltInstruction, BltuInstruction, BneInstruction, JalInstruction,
    JalrInstruction, LbInstruction, LbuInstruction, LhInstruction, LhuInstruction, LuiInstruction,
    LwInstruction, OrInstruction, SbInstruction, ShInstruction, SllInstruction, SltInstruction,
    SltuInstruction, SraInstruction, SrlInstruction, SubInstruction, SwInstruction, XorInstruction,
};

// RV32M Multiply extension
mod m;
pub use m::{
    DivInstruction, DivuInstruction, MulInstruction, MulhInstruction, MulhsuInstruction,
    MulhuInstruction, RemInstruction, RemuInstruction,
};

pub use nexus_common::cpu::InstructionResult;

// Macro implementations
pub(crate) mod macros;
