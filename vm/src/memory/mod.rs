mod fixed;
mod memory_image;
mod page;
mod paged_memory;
mod unified;
mod variable;

pub use nexus_common::memory::traits::{
    LoadOp, LoadOps, MemAccessSize, MemoryProcessor, MemoryRecord, MemoryRecords, Mode, StoreOp,
    StoreOps, NA, RO, RW, WO,
};

pub use fixed::FixedMemory;
pub use memory_image::MemorySegmentImage;
pub use paged_memory::PagedMemory;
pub use unified::{Modes, UnifiedMemory};
pub use variable::VariableMemory;
