mod fixed;
mod unified;
mod variable;

use nexus_common::memory::traits::get_shift_and_mask;
pub use nexus_common::memory::traits::{MemAccessSize, MemoryProcessor, Mode, NA, RO, RW, WO};

pub use fixed::FixedMemory;
pub use unified::UnifiedMemory;
pub use variable::VariableMemory;
