mod fixed;
mod r#trait;
mod variable;

use r#trait::get_shift_and_mask;
pub use r#trait::{MemAccessSize, MemoryProcessor};

pub use fixed::FixedMemory;
pub use variable::VariableMemory;
