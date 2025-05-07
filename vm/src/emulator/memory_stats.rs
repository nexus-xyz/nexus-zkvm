//! Memory Statistics and Optimization for RISC-V Emulator
//!
//! This module provides functionality to track memory usage statistics and optimize
//! memory layout based on actual usage patterns during program execution.
//!
//! # Key Components
//!
//! - `MemoryStats`: A struct that keeps track of memory access statistics.
//!
//! # Features
//!
//! - Tracks the maximum heap access and minimum stack access addresses.
//! - Updates statistics based on load and store operations during program execution.
//! - Creates an optimized `LinearMemoryLayout` based on observed memory usage.
//!
//! # Memory Layout Optimization
//!
//! The `MemoryStats` struct helps in optimizing memory layout by:
//! 1. Tracking the highest heap access and lowest stack access during program execution.
//! 2. Using these statistics to create a more efficient `LinearMemoryLayout`.
//!
//! This optimization can lead to more efficient memory usage by:
//! - Allocating only the necessary amount of heap space based on actual usage.
//! - Adjusting the stack size to match the maximum observed stack depth.
//!
//! # Implementation Details
//!
//! - The `update` method processes `LoadOp` and `StoreOp` operations to track memory accesses.
//! - The `create_optimized_layout` method generates a new `LinearMemoryLayout` based on the observed statistics.
//! - The stack pointer is used directly to determine the minimum stack access, ensuring that the full reserved stack frame is respected.
//!
//! # Note
//!
//! - This implementation prioritizes safety over potential further optimizations
//!   that could be achieved by tracking actual stack accesses.

use crate::emulator::layout::LinearMemoryLayout;
use crate::error::Result;

#[derive(Debug)]
pub struct MemoryStats {
    max_heap_access: u32,
    min_stack_access: u32,
    heap_bottom: u32,
    stack_top: u32,
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl MemoryStats {
    pub fn new(heap_bottom: u32, stack_top: u32) -> Self {
        Self {
            max_heap_access: heap_bottom,
            min_stack_access: stack_top,
            heap_bottom,
            stack_top,
        }
    }

    pub fn register_heap_allocation(&mut self, alloc_addr: u32, alloc_bytes: u32) {
        self.max_heap_access = self.max_heap_access.max(alloc_addr + alloc_bytes);
    }

    pub fn update_stack_access(&mut self, stack_pointer: u32) {
        if stack_pointer > 0 && stack_pointer < self.min_stack_access {
            self.min_stack_access = stack_pointer;
        }
    }

    /// Create an optimized linear memory layout based on the memory stats.
    ///
    /// Note: `input_size` is the size of the public input, and `output_size` is the size of the
    /// actual public output. Callers should *not* include the extra word of length or return code
    /// in these sizes.
    pub fn create_optimized_layout(
        &self,
        program_size: u32,
        ad_size: u32,
        input_size: u32,
        output_size: u32,
    ) -> Result<LinearMemoryLayout> {
        LinearMemoryLayout::try_new(
            self.max_heap_access - self.heap_bottom,
            self.stack_top - self.min_stack_access,
            input_size,
            output_size,
            program_size,
            ad_size,
        )
    }

    /// Returns the total number of addresses under RAM memory checking.
    pub fn get_tracked_ram_size(&self, input_size: u32, output_size: u32) -> u32 {
        let heap_size = self.max_heap_access - self.heap_bottom;
        let stack_size = self.stack_top - self.min_stack_access;
        let total = [heap_size, stack_size, input_size, output_size]
            .iter()
            .try_fold(0u32, |acc, &val| acc.checked_add(val))
            .expect("overflow");
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_optimized_layout() {
        let mut stats: MemoryStats = MemoryStats::new(0, 0x10000);
        let stack_pointer = 0x1000;

        // Create heap accesses
        stats.register_heap_allocation(0x100, 0x100);

        // Create stack accesses
        stats.update_stack_access(stack_pointer + 0x100);
        stats.update_stack_access(stack_pointer);
        stats.update_stack_access(stack_pointer + 0x200);

        let program_size = 0x300;
        let ad_size = 0x100;

        let layout = stats
            .create_optimized_layout(program_size, ad_size, 0, 0)
            .unwrap();

        assert_eq!(layout.public_input_end(), 0x38C);
        assert_eq!(layout.public_output_end(), 0x390); // aka heap start
        assert_eq!(layout.heap_end(), 0x590);
        assert_eq!(layout.stack_bottom(), 0x590);
        assert_eq!(layout.stack_top(), 0xF590);
        assert_eq!(layout.ad_end(), 0xF690);
    }
}
