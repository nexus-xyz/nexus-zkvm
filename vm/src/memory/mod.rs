mod fixed;
mod variable;

use nexus_common::memory::traits::get_shift_and_mask;
pub use nexus_common::memory::traits::{MemAccessSize, MemoryProcessor};

pub use fixed::FixedMemory;
pub use variable::VariableMemory;
