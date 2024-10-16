mod fixed;
mod unified;
mod variable;

pub use nexus_common::memory::traits::{
    LoadOp, LoadOps, MemAccessSize, MemoryProcessor, MemoryRecord, MemoryRecords, Mode, StoreOp,
    StoreOps, NA, RO, RW, WO,
};

pub use fixed::FixedMemory;
pub use unified::UnifiedMemory;
pub use variable::VariableMemory;
