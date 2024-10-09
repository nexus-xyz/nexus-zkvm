use crate::elf::WORD_SIZE;
use crate::error::{Result, VMError};

// see runtime
const MEMORY_GAP: u32 = 0x1000;

// nb: all measurements are in terms of virtual memory
#[derive(Clone, Copy, Debug)]
pub struct LinearMemoryLayout {
    // start of the gap between heap and stack
    gap: u32,
    // bottom of the stack
    stack_bottom: u32,
    // top of the stack/start of public input
    stack_top: u32,
    // location of the panic byte
    panic: u32,
    // start of the public output
    public_output: u32,
    // start of the program memory
    program: u32,
    // start of the associated data hash
    ad_hash: u32,
    // end of the memory
    end: u32,
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

        if self.gap_end() - self.gap_start() > MEMORY_GAP + WORD_SIZE {
            return Err(VMError::InvalidMemoryLayout);
        }

        // enforce order
        if self.ad_hash_start() <= self.program_start()
            || self.program_start() <= self.public_output_start()
            || self.public_output_start() <= self.panic()
            || self.panic() <= self.public_input_start()
            || self.public_input_start() <= self.stack_top()
            || self.stack_top() <= self.stack_bottom()
            || self.stack_bottom() <= self.gap_start()
            || self.gap_start() <= self.heap_start()
            || self.heap_start() <= self.registers_start()
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
        ad_hash_size: u32,
    ) -> Self {
        let gap = 0x1000 + max_heap_size; // registers take 0x1000 bytes
        let stack_bottom = gap + MEMORY_GAP;
        let stack_top = stack_bottom + max_stack_size;
        let panic = stack_top + WORD_SIZE + public_input_size; // stack_top | {input_size} | {input}
        let public_output = panic + WORD_SIZE;
        let program = public_output + public_output_size;
        let ad_hash = program + program_size;
        let end = ad_hash + ad_hash_size;

        Self {
            gap,
            stack_bottom,
            stack_top,
            panic,
            public_output,
            program,
            ad_hash,
            end,
        }
    }

    pub fn new(
        max_heap_size: u32,
        max_stack_size: u32,
        public_input_size: u32,
        public_output_size: u32,
        program_size: u32,
        ad_hash_size: u32,
    ) -> Result<Self> {
        let ml = Self::new_unchecked(
            max_heap_size,
            max_stack_size,
            public_input_size,
            public_output_size,
            program_size,
            ad_hash_size,
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
        32 * WORD_SIZE
    }

    pub const fn heap_start(&self) -> u32 {
        32 * WORD_SIZE
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
        self.stack_top - WORD_SIZE
    }

    pub fn public_input_start(&self) -> u32 {
        self.stack_top
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
        self.program
    }

    pub fn program_start(&self) -> u32 {
        self.program
    }

    pub fn program_end(&self) -> u32 {
        self.ad_hash
    }

    pub fn ad_hash_start(&self) -> u32 {
        self.ad_hash
    }

    pub fn ad_hash_end(&self) -> u32 {
        self.end
    }
}
