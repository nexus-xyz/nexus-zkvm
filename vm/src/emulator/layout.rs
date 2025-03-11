//! Memory Layout for RISC-V Emulator
//!
//! This module defines the `LinearMemoryLayout` struct, which represents the memory layout
//! for a RISC-V emulator. It provides a structured way to manage different memory regions
//! such as program space, input/output areas, heap, and stack.
//!
//! # Key Components
//!
//! - `LinearMemoryLayout`: A struct that defines the memory layout with various segments.
//!
//! # Memory Segments
//!
//! The layout includes the following memory segments:
//! - Registers
//! - Program
//! - Public Input
//! - Associated Data (AD)
//! - Exit Code
//! - Public Output
//! - Heap
//! - Memory Gap
//! - Stack
//!
//! # Features
//!
//! - Configurable memory layout with customizable sizes for different segments.
//! - Validation of memory layout to ensure correct ordering and minimum size requirements.
//! - Methods to access start and end addresses of each memory segment.
//! - Support for serialization and deserialization of the layout.
//!
//! # Usage
//!
//! ```rust
//! use nexus_vm::emulator::LinearMemoryLayout;
//!
//! // Create a new memory layout
//! let layout = LinearMemoryLayout::new(
//!     0x100000, // max_heap_size
//!     0x100000, // max_stack_size
//!     0x1000,   // public_input_size
//!     0x1000,   // public_output_size
//!     0x10000,  // program_size
//!     0x100     // ad_size
//! ).unwrap();
//!
//! // Access memory segment boundaries
//! let heap_start = layout.heap_start();
//! let stack_top = layout.stack_top();
//! ```
//!
//! # Memory Layout Visualization
//!
//! ```text
//! +------------------+ 0x00000000
//! |     Registers    | (32 * 4 bytes)
//! +------------------+ 0x00000080
//! | Public Input     |
//! | Start Location   |
//! +------------------+ 0x00000084
//! | Public Output    |
//! | Start Location   |
//! +------------------+ 0x00000088
//! |    (unused)      |
//! +------------------+ ELF_TEXT_START
//! |      Program     |
//! +------------------+
//! |   Public Input   |
//! +------------------+
//! |  Associated Data |
//! +------------------+
//! |    Exit Code     |
//! +------------------+
//! |  Public Output   |
//! +------------------+
//! |       Heap       |
//! +------------------+
//! |    Memory Gap    | (>= MEMORY_GAP bytes)
//! +------------------+
//! |      Stack       |
//! +------------------+ stack_top (points to last accessible word)
//! ```
//!
//! # Notes
//!
//! - All measurements in this module are in terms of virtual memory addresses.
//! - WORD_SIZE is 4 bytes.
//! - NUM_REGISTERS is 32.
//! - The `*_end()` methods point to one byte past the end of the segment (C++ `.end()` style).
//! - `stack_top()` points to the last accessible word in the stack segment.
//! - The memory gap size is at least `MEMORY_GAP` and no more than `MEMORY_GAP + WORD_SIZE`.
//! - The layout enforces a strict ordering of segments as shown in the visualization.
//!
//! # Implementation Details
//!
//! - The `LinearMemoryLayout` struct uses `u32` values to represent memory addresses.
//! - The `new()` method creates a validated layout, while `new_unchecked()` creates a layout without validation.
//! - The `validate()` method ensures that the memory layout is correct and all segments are in the proper order.
//! - Various getter methods are provided to access the start and end addresses of each memory segment.
//!
//! This module is crucial for managing the memory layout in the RISC-V emulator,
//! ensuring proper allocation and access to different memory regions during program execution.
use crate::error::{Result, VMError};
use nexus_common::constants::{ELF_TEXT_START, MEMORY_GAP, NUM_REGISTERS, WORD_SIZE};
use nexus_common::word_align;
use serde::{Deserialize, Serialize};

// nb: all measurements are in terms of virtual memory
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LinearMemoryLayout {
    // start of the public input
    public_input: u32,
    // start of the associated data hash
    ad: u32,
    // location of the exit code
    exit_code: u32,
    // start of the public output
    public_output: u32,
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
            || self.heap_start() < self.public_output_start()
            || self.public_output_start() <= self.exit_code()
            || self.exit_code() < self.ad_start()
            || self.ad_start() <= self.public_input_start() // First word of input stores input length, so must be non-empty
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
        let ad = public_input + public_input_size + WORD_SIZE as u32;
        let exit_code = ad + ad_size;
        let public_output = exit_code + WORD_SIZE as u32;
        let heap = public_output + public_output_size;
        let gap = heap + max_heap_size;
        let stack_bottom = gap + MEMORY_GAP;
        let stack_top = stack_bottom + max_stack_size;

        Self {
            public_input,
            ad,
            exit_code,
            public_output,
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
            word_align!(max_heap_size as usize) as u32,
            word_align!(max_stack_size as usize) as u32,
            word_align!(public_input_size as usize) as u32,
            word_align!(public_output_size as usize) as u32,
            word_align!(program_size as usize) as u32,
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
        self.ad
    }

    pub fn ad_start(&self) -> u32 {
        self.ad
    }

    pub fn ad_end(&self) -> u32 {
        self.exit_code
    }

    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }

    pub fn public_output_start(&self) -> u32 {
        self.public_output
    }

    pub fn public_output_end(&self) -> u32 {
        self.heap
    }

    pub fn public_output_addresses(&self) -> impl Iterator<Item = u32> {
        self.public_output_start()..self.public_output_end()
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

    pub fn tracked_ram_size(&self, static_memory_size: usize) -> usize {
        let stack_size: usize =
            self.stack_top
                .checked_sub(self.stack_bottom)
                .expect("stack top should be above stack bottom") as usize;
        let heap_size = self
            .heap
            .checked_sub(self.heap_start())
            .expect("heap should be above heap start") as usize;
        let public_input_size =
            self.public_input_end()
                .checked_sub(self.public_input_start())
                .expect("public input end should be above public input start") as usize;
        let public_output_size = self
            .public_output_end()
            .checked_sub(self.public_output_start())
            .expect("public output end should be above public output start")
            as usize;
        let exit_code_size = WORD_SIZE;
        // program, registers, and ad are not under RAM checking. omitted.
        let total = [
            static_memory_size,
            stack_size,
            heap_size,
            public_input_size,
            public_output_size,
            exit_code_size,
        ]
        .iter()
        .try_fold(0usize, |acc, &val| acc.checked_add(val))
        .expect("overflow");
        total
    }
}
