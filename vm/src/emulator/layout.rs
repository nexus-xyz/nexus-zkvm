use crate::error::{Result, VMError};
use nexus_common::constants::{ELF_TEXT_START, MEMORY_GAP, NUM_REGISTERS, WORD_SIZE};
use nexus_common::word_align;
use serde::{Deserialize, Serialize};

// nb: all measurements are in terms of virtual memory
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LinearMemoryLayout {
    // start of the public input
    public_input: u32,
    // location of the panic byte
    panic: u32,
    // start of the public output
    public_output: u32,
    // start of the associated data hash
    ad: u32,
    // start of the heap
    heap: u32,
    // start of the gap between heap and stack
    gap: u32,
    // bottom of the stack
    stack_bottom: u32,
    // top of the stack
    stack_top: u32,
}

impl Default for LinearMemoryLayout {
    fn default() -> LinearMemoryLayout {
        // a suitable default for testing
        LinearMemoryLayout::new_unchecked(0x800000, 0x100000, 0x0, 0x0, 0x80000, 0x0)
    }
}

#[allow(dead_code)]
impl LinearMemoryLayout {
    fn validate(&self) -> Result<()> {
        // gap should be at least MEMORY_GAP (see runtime) and no more than MEMORY_GAP + WORD_SIZE
        if self.gap_end() - self.gap_start() < MEMORY_GAP {
            return Err(VMError::InvalidMemoryLayout);
        }

        if self.gap_end() - self.gap_start() > MEMORY_GAP + WORD_SIZE as u32 {
            return Err(VMError::InvalidMemoryLayout);
        }

        // Enforce order.
        if self.stack_top() < self.stack_bottom()
            || self.stack_bottom() < self.gap_start()
            || self.gap_start() < self.heap_start()
            || self.heap_start() < self.ad_start()
            || self.ad_start() < self.public_output_start()
            || self.public_output_start() <= self.panic()
            || self.panic() <= self.public_input_start() // First word of input stores input length, so must be non-empty
            || self.public_input_start() <= self.program_start() // Program assumed to be non-empty
            || self.program_start() <= self.public_output_start_location()
        {
            return Err(VMError::InvalidMemoryLayout);
        }

        Ok(())
    }

    pub fn new_unchecked(
        max_heap_size: u32,
        max_stack_size: u32,
        public_input_size: u32,
        public_output_size: u32,
        program_size: u32,
        ad_size: u32,
    ) -> Self {
        let public_input = ELF_TEXT_START + program_size;
        let panic = public_input + public_input_size + WORD_SIZE as u32;
        let public_output = panic + WORD_SIZE as u32;
        let ad = public_output + public_output_size;
        let heap = ad + ad_size;
        let gap = heap + max_heap_size;
        let stack_bottom = gap + MEMORY_GAP;
        let stack_top = stack_bottom + max_stack_size;

        Self {
            public_input,
            panic,
            public_output,
            ad,
            heap,
            gap,
            stack_bottom,
            stack_top,
        }
    }

    pub fn new(
        max_heap_size: u32,
        max_stack_size: u32,
        public_input_size: u32,
        public_output_size: u32,
        program_size: u32,
        ad_size: u32,
    ) -> Result<Self> {
        let ml = Self::new_unchecked(
            max_heap_size,
            max_stack_size,
            word_align!(public_input_size as usize) as u32,
            word_align!(public_output_size as usize) as u32,
            program_size,
            word_align!(ad_size as usize) as u32,
        );
        ml.validate()?;

        Ok(ml)
    }

    // The `*_end` point to one byte past the end of the segment (c++ `.end()` style)
    // However, `stack_top` instead points to the last accessible word in the segment

    pub const fn registers_start(&self) -> u32 {
        0
    }

    pub const fn registers_end(&self) -> u32 {
        NUM_REGISTERS * WORD_SIZE as u32
    }

    pub const fn public_input_start_location(&self) -> u32 {
        NUM_REGISTERS * WORD_SIZE as u32
    }

    pub const fn public_output_start_location(&self) -> u32 {
        (NUM_REGISTERS + 1) * WORD_SIZE as u32
    }

    pub const fn program_start(&self) -> u32 {
        assert!(ELF_TEXT_START >= self.public_output_start_location() + WORD_SIZE as u32);
        ELF_TEXT_START
    }

    pub fn program_end(&self) -> u32 {
        self.public_input
    }

    pub fn public_input_start(&self) -> u32 {
        self.public_input
    }

    pub fn public_input_end(&self) -> u32 {
        self.panic
    }

    pub fn panic(&self) -> u32 {
        self.panic
    }

    pub fn public_output_start(&self) -> u32 {
        self.public_output
    }

    pub fn public_output_end(&self) -> u32 {
        self.ad
    }

    pub fn ad_start(&self) -> u32 {
        self.ad
    }

    pub fn ad_end(&self) -> u32 {
        self.heap
    }

    pub const fn heap_start(&self) -> u32 {
        self.heap
    }

    pub fn heap_end(&self) -> u32 {
        self.gap
    }

    pub fn gap_start(&self) -> u32 {
        self.gap
    }

    pub fn gap_end(&self) -> u32 {
        self.stack_bottom
    }

    pub fn stack_bottom(&self) -> u32 {
        self.stack_bottom
    }

    pub fn stack_top(&self) -> u32 {
        self.stack_top - WORD_SIZE as u32
    }
}
