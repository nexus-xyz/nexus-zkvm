use nexus_common::constants::WORD_SIZE;

use crate::emulator::layout::LinearMemoryLayout;
use crate::{
    error::Result,
    memory::{LoadOp, StoreOp},
};
use std::cmp::max;
use std::collections::HashSet;

#[derive(Debug)]
pub struct MemoryStats {
    pub max_heap_access: u32,
    pub min_stack_access: u32,
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

    /// Update the stack pointer statistics. This check is extremely simple: if the stack pointer is
    /// less than the current minimum, update it.
    #[inline(always)]
    pub fn update_stack(&mut self, stack_pointer: u32) {
        if 0 < stack_pointer && stack_pointer < self.min_stack_access {
            self.min_stack_access = stack_pointer;
        }
    }

    /// Update the heap statistics based on the given load and store operations.
    ///
    /// If the memory operations have touched memory between the heap top and the stack pointer,
    /// then the heap top is moved up to include the current access.
    pub fn update_heap(
        &mut self,
        load_ops: &HashSet<LoadOp>,
        store_ops: &HashSet<StoreOp>,
        stack_pointer: u32,
    ) -> Result<()> {
        // Collect all memory accesses.
        let max_heap_access = load_ops
            .iter()
            .map(|op| op.get_address())
            .chain(store_ops.iter().map(|op| op.get_address()))
            // Memory access above the stack pointer are not heap accesses.
            .filter(|addr| *addr < stack_pointer)
            .max();

        self.max_heap_access = max(self.max_heap_access, max_heap_access.unwrap_or(0));

        Ok(())
    }

    /// Create an optimized linear memory layout based on the memory stats.
    pub fn create_optimized_layout(
        &self,
        program_size: u32,
        ad_size: u32,
        input_size: u32,
        output_size: u32,
    ) -> Result<LinearMemoryLayout> {
        // The extra words counteract mysterious and subtle off-by-one errors.
        LinearMemoryLayout::new(
            self.max_heap_access - self.heap_bottom + WORD_SIZE as u32 * 2,
            self.stack_top - self.min_stack_access + WORD_SIZE as u32 * 2,
            input_size,
            output_size,
            program_size,
            ad_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{LoadOp, MemAccessSize, StoreOp};

    #[test]
    fn test_update_data_region() {
        let mut sizes = MemoryStats::new(0, 1000000);
        let mut load_ops = HashSet::new();
        let mut store_ops = HashSet::new();
        let stack_pointer = 1000;

        // Heap accesses (below stack pointer).
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 500, 0));
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 600, 0, 0));

        // Stack accesses (above stack pointer).
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 1100, 0));
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 1200, 0, 0));

        sizes.update_stack(stack_pointer);
        sizes
            .update_heap(&load_ops, &store_ops, stack_pointer)
            .unwrap();
        assert_eq!(sizes.max_heap_access, 600);
        assert_eq!(sizes.min_stack_access, 1000);
    }

    #[test]
    fn test_create_optimized_layout() {
        let mut stats = MemoryStats::new(0, 1000000);
        let stack_pointer = 3000;

        // Create heap accesses (below stack pointer).
        let mut load_ops = HashSet::new();
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 1000, 0));
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 800, 0));

        // Create stack accesses (above stack pointer).
        let mut store_ops = HashSet::new();
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 3000, 0, 0));
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 3500, 0, 0));

        // Update data region (heap and stack).
        stats.update_stack(stack_pointer);
        stats
            .update_heap(&load_ops, &store_ops, stack_pointer)
            .unwrap();

        let mut more_load_ops = HashSet::new();
        more_load_ops.insert(LoadOp::Op(MemAccessSize::Word, 500, 0));
        stats
            .update_heap(&more_load_ops, &HashSet::new(), stack_pointer)
            .unwrap();

        let mut more_store_ops = HashSet::new();
        more_store_ops.insert(StoreOp::Op(MemAccessSize::Word, 800, 0, 0));
        stats
            .update_heap(&HashSet::new(), &more_store_ops, stack_pointer)
            .unwrap();

        let program_size = 300;
        let ad_size = 100;

        let layout = stats
            .create_optimized_layout(program_size, ad_size, 0, 0)
            .unwrap();

        assert_eq!(layout.heap_end(), 5512);
        assert_eq!(layout.stack_bottom(), 9608);
        assert_eq!(layout.stack_top(), 1006612);
        assert_eq!(layout.public_input_end(), 4400);
        assert_eq!(layout.ad_end(), 4500);
        assert_eq!(layout.public_output_end(), 4504);
    }
}
