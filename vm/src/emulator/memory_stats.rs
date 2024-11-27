use crate::emulator::layout::LinearMemoryLayout;
use crate::{
    error::Result,
    memory::{LoadOp, StoreOp},
};
use std::cmp::{max, min};
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
            max_heap_access: 0,
            min_stack_access: u32::MAX,
            heap_bottom,
            stack_top,
        }
    }

    /// Update the memory stats based on load and store operations.
    pub fn update(
        &mut self,
        load_ops: HashSet<LoadOp>,
        store_ops: HashSet<StoreOp>,
        stack_pointer: u32,
    ) -> Result<()> {
        // Collect all memory accesses.
        let memory_accesses: HashSet<u32> = load_ops
            .iter()
            .map(|op| op.get_address())
            .chain(store_ops.iter().map(|op| op.get_address()))
            .collect();

        // Find the highest memory access in the heap.
        self.max_heap_access = max(
            self.max_heap_access,
            *memory_accesses
                .iter()
                .filter(|&addr| addr < &stack_pointer)
                .max()
                .unwrap_or(&0),
        );

        // For safety, we just check the stack pointer directly rather than looking for the lowest memory access.
        // This ensures we respect the full stack frame that was reserved, even if not all of it is used.
        // We could optimize this in the future by tracking actual stack accesses if needed.
        self.min_stack_access = min(self.min_stack_access, stack_pointer);
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
        LinearMemoryLayout::new(
            self.max_heap_access - self.heap_bottom,
            self.stack_top - self.min_stack_access,
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
        let mut sizes = MemoryStats::new(0, 0);
        let mut load_ops = HashSet::new();
        let mut store_ops = HashSet::new();
        let stack_pointer = 1000;

        // Heap accesses (below stack pointer).
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 500, 0));
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 600, 0, 0));

        // Stack accesses (above stack pointer).
        load_ops.insert(LoadOp::Op(MemAccessSize::Word, 1100, 0));
        store_ops.insert(StoreOp::Op(MemAccessSize::Word, 1200, 0, 0));

        sizes.update(load_ops, store_ops, stack_pointer).unwrap();
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
        stats
            .update(
                load_ops.iter().cloned().collect(),
                store_ops.iter().cloned().collect(),
                stack_pointer,
            )
            .unwrap();

        let mut more_load_ops = HashSet::new();
        more_load_ops.insert(LoadOp::Op(MemAccessSize::Word, 500, 0));
        stats
            .update(more_load_ops, HashSet::new(), stack_pointer)
            .unwrap();

        let mut more_store_ops = HashSet::new();
        more_store_ops.insert(StoreOp::Op(MemAccessSize::Word, 800, 0, 0));
        stats
            .update(HashSet::new(), more_store_ops, stack_pointer)
            .unwrap();

        let program_size = 300;
        let ad_size = 100;

        let layout = stats
            .create_optimized_layout(program_size, ad_size, 0, 0)
            .unwrap();

        assert_eq!(layout.heap_end(), 5096);
        assert_eq!(layout.stack_bottom(), 9192);
        assert_eq!(layout.stack_top(), 1006188);
        assert_eq!(layout.public_input_end(), 1006196);
        assert_eq!(layout.public_output_end(), 1006200);
    }
}
