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
//! - Input/Output Segment Addresses
//! - Program
//! - Public Input
//! - Exit Code
//! - Public Output
//! - Heap
//! - Stack
//! - Associated Data (AD)
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
//! let layout = LinearMemoryLayout::try_new(
//!     None,     // (optional) static_ram
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
//! +------------------+ 0x00000088 = ELF_TEXT_START
//! |  Program (Text)  |
//! |   Static Data    |
//! |       BSS        |
//! +------------------+
//! |   Public Input   |
//! +------------------+
//! |    Exit Code     |
//! +------------------+
//! |  Public Output   |
//! +------------------+
//! |       Heap       |
//! +------------------+
//! |      Stack       |
//! +------------------+
//! |  Associated Data |
//! +------------------+
//! ```
//!
//! # Notes
//!
//! - All measurements in this module are in terms of virtual memory addresses.
//! - WORD_SIZE is 4 bytes.
//! - NUM_REGISTERS is 32.
//! - The `*_end()` and `stack_top()` methods point to one byte past the end of the segment (C++
//!   `.end()` style).
//! - The layout enforces a strict ordering of segments as shown in the visualization.
//!
//! # Implementation Details
//!
//! - The `LinearMemoryLayout` struct uses `u32` values to represent memory addresses.
//! - The `validate()` method ensures that the memory layout is correct and all segments are in the proper order.
//! - Various getter methods are provided to access the start and end addresses of each memory segment.
//!
//! This module is crucial for managing the memory layout in the RISC-V emulator,
//! ensuring proper allocation and access to different memory regions during program execution.
use std::fmt::Display;

use crate::error::Result;
use nexus_common::{
    constants::{
        ELF_TEXT_START, NUM_REGISTERS, PUBLIC_INPUT_ADDRESS_LOCATION,
        PUBLIC_OUTPUT_ADDRESS_LOCATION, WORD_SIZE,
    },
    memory::alignment::Alignable,
};
use serde::{Deserialize, Serialize};

/// Memory Layout for the trace-generating pass of the emulator. It is an invariant that all
/// sentinels described by this layout are word-aligned. It is also an invariant that any
/// `LinearMemoryLayout` describes a legal memory layout according to our specs. See `validate`
/// for details.
// nb: all measurements are in terms of virtual memory
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LinearMemoryLayout {
    // range of static ram (exclusive of endpoint), if any
    //
    // Safety: this assumes that the ram is contiguous, even though it
    //         may include multiple elf sections (.data, .bss, and etc)
    //
    //         this appears to be a safe assumption with rustc, and the
    //         emulator frequently assumes it, but may not be true for
    //         other compilers and so may need to be checked in the future
    static_ram: Option<(u32, u32)>,
    // start of the public input
    public_input: u32,
    // location of the exit code
    exit_code: u32,
    // start of the public output
    public_output: u32,
    // start of the heap
    heap: u32,
    // bottom of the stack
    stack_bottom: u32,
    // top of the stack, start of ad
    stack_top: u32,
    // end of ad and the whole memory space
    end: u32,
}

impl Default for LinearMemoryLayout {
    fn default() -> LinearMemoryLayout {
        // a suitable default for testing
        LinearMemoryLayout::try_new(None, 0x800000, 0x100000, 0x0, 0x0, 0x80000, 0x0).unwrap()
    }
}

impl LinearMemoryLayout {
    fn validate(&self) -> Result<()> {
        // Enforce order & spacing.
        assert!(self.end == self.ad_end());
        assert!(self.ad_start() <= self.ad_end());
        assert!(self.ad_start() == self.stack_top());
        assert!(self.stack_bottom() <= self.stack_top());
        assert!(self.stack_bottom() == self.heap_end());
        assert!(self.heap_start() <= self.heap_end());
        assert!(self.heap_start() == self.public_output_end());
        assert!(self.public_output_start() <= self.public_output_end());
        assert!(self.public_output_start() == self.exit_code() + WORD_SIZE as u32);
        assert!(self.public_input_end() == self.exit_code());
        assert!(self.public_input_end() - self.public_input_start() >= WORD_SIZE as u32);
        assert!(self.program_end() == self.public_input_start());

        if let Some(static_ram) = self.static_ram_range() {
            assert!(static_ram.0 < static_ram.1);
            assert!(static_ram.0 >= self.program_start());
            assert!(static_ram.1 <= self.program_end());
        }

        // Enforce alignment. Note: static ram end don't need to be word-aligned.
        self.public_input.assert_word_aligned();
        self.exit_code.assert_word_aligned();
        self.public_output.assert_word_aligned();
        self.heap.assert_word_aligned();
        self.stack_bottom.assert_word_aligned();
        self.stack_top.assert_aligned_to::<0x10>();

        Ok(())
    }

    /// Attempt to create a new, validated `LinearMemoryLayout`. This function will never produce an
    /// invalid layout.
    ///
    /// `public_input_size` should represent only the size of the raw input data. It should *not*
    /// account for the memory occupied by the length prepended to the input in guest memory.
    ///
    /// `public_output_size` should represent only the size of the raw output data. It should *not*
    /// account for the memory occupied by the program's return code.
    pub fn try_new(
        static_ram: Option<(u32, u32)>,
        max_heap_size: u32,
        max_stack_size: u32,
        public_input_size: u32,
        public_output_size: u32,
        program_size: u32,
        ad_size: u32,
    ) -> Result<Self> {
        let public_input = ELF_TEXT_START + program_size;
        assert!(public_input.is_word_aligned());
        // Add an extra word for the length of the public input.
        let exit_code = (public_input + public_input_size + WORD_SIZE as u32).word_align();
        let public_output = exit_code + WORD_SIZE as u32;
        let heap = (public_output + public_output_size).word_align();
        let stack_bottom = (heap + max_heap_size).word_align();
        let stack_top = (stack_bottom + max_stack_size).align_to::<0x10>();
        let ad = stack_top;
        let end = ad + ad_size;

        let res = Self {
            static_ram,
            public_input,
            exit_code,
            public_output,
            heap,
            stack_bottom,
            stack_top,
            end,
        };

        res.validate()?;

        Ok(res)
    }

    // The `*_end()` point to one byte past the end of the segment (c++ `.end()` style)
    // `stack_top()` behaves the same as the `*_end` functions

    /// Guaranteed to be word-aligned.
    pub const fn registers_start(&self) -> u32 {
        0
    }

    /// Guaranteed to be word-aligned.
    pub const fn registers_end(&self) -> u32 {
        NUM_REGISTERS * WORD_SIZE as u32
    }

    /// Guaranteed to be word-aligned.
    pub const fn public_input_address_location(&self) -> u32 {
        PUBLIC_INPUT_ADDRESS_LOCATION
    }

    /// Guaranteed to be word-aligned.
    pub const fn public_output_address_location(&self) -> u32 {
        PUBLIC_OUTPUT_ADDRESS_LOCATION
    }

    /// Guaranteed to be word-aligned.
    pub const fn program_start(&self) -> u32 {
        assert!(ELF_TEXT_START >= self.public_output_address_location() + WORD_SIZE as u32);
        ELF_TEXT_START
    }

    pub fn static_ram_range(&self) -> Option<(u32, u32)> {
        self.static_ram
    }

    pub fn static_ram_start(&self) -> Option<u32> {
        self.static_ram_range()
            .map(|static_ram_range| static_ram_range.0)
    }

    pub fn static_ram_end(&self) -> Option<u32> {
        self.static_ram_range()
            .map(|static_ram_range| static_ram_range.1)
    }

    /// Guaranteed to be word-aligned.
    pub fn program_end(&self) -> u32 {
        self.public_input
    }

    /// Guaranteed to be word-aligned.
    pub fn public_input_start(&self) -> u32 {
        self.public_input
    }

    /// Guaranteed to be word-aligned.
    pub fn public_input_end(&self) -> u32 {
        self.exit_code
    }

    /// Guaranteed to be word-aligned.
    pub fn exit_code(&self) -> u32 {
        self.exit_code
    }

    /// Guaranteed to be word-aligned.
    pub fn public_output_start(&self) -> u32 {
        self.public_output
    }

    /// Guaranteed to be word-aligned.
    pub fn public_output_end(&self) -> u32 {
        self.heap
    }

    /// Guaranteed to be word-aligned.
    pub fn public_output_addresses(&self) -> impl Iterator<Item = u32> {
        self.public_output_start()..self.public_output_end()
    }

    /// Guaranteed to be word-aligned.
    pub const fn heap_start(&self) -> u32 {
        self.heap
    }

    /// Guaranteed to be word-aligned.
    pub fn heap_end(&self) -> u32 {
        self.stack_bottom
    }
    /// Guaranteed to be word-aligned.
    pub fn stack_bottom(&self) -> u32 {
        self.stack_bottom
    }

    /// Guaranteed to be word-aligned.
    pub fn stack_top(&self) -> u32 {
        self.stack_top
    }

    /// Guaranteed to be word-aligned.
    pub fn ad_start(&self) -> u32 {
        self.stack_top
    }

    /// Guaranteed to be word-aligned.
    pub fn ad_end(&self) -> u32 {
        self.end
    }

    pub fn tracked_ram_size(&self, static_memory_size: usize) -> usize {
        let stack_size: usize =
            self.stack_top
                .checked_sub(self.stack_bottom)
                .expect("stack top should be above stack bottom") as usize;
        let heap_size = self
            .heap_end()
            .checked_sub(self.heap_start())
            .expect("heap end should be above heap start") as usize;
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

impl Display for LinearMemoryLayout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "LinearMemoryLayout {{")?;
        writeln!(
            f,
            "  stack: {:#X}--{:#X}",
            self.stack_bottom, self.stack_top
        )?;
        writeln!(
            f,
            "  heap: {:#X}--{:#X}",
            self.heap_start(),
            self.heap_end()
        )?;
        writeln!(
            f,
            "  public_output: {:#X}--{:#X}",
            self.public_output_start(),
            self.public_output_end()
        )?;
        writeln!(f, "  exit_code: {:#X}", self.exit_code())?;
        writeln!(f, "  ad: {:#X}--{:#X}", self.ad_start(), self.ad_end())?;
        writeln!(
            f,
            "  public_input: {:#X}--{:#X}",
            self.public_input_start(),
            self.public_input_end()
        )?;
        writeln!(
            f,
            "  program: {:#X}--{:#X}",
            self.program_start(),
            self.program_end()
        )?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::LinearMemoryLayout;

    #[test]
    fn tracked_ram_size_includes_heap_nonzero() {
        // Construct a layout with a non-zero heap and stack sizes
        let max_heap_size: u32 = 0x200; // 512 bytes
        let max_stack_size: u32 = 0x300; // 768 bytes
        let public_input_size: u32 = 0x20; // 32 bytes (raw)
        let public_output_size: u32 = 0x40; // 64 bytes (raw)
        let program_size: u32 = 0x1000; // 4096 bytes
        let ad_size: u32 = 0x10; // 16 bytes

        let layout = LinearMemoryLayout::try_new(
            None,
            max_heap_size,
            max_stack_size,
            public_input_size,
            public_output_size,
            program_size,
            ad_size,
        )
        .unwrap();

        // Compute expected sizes from the layout getters to include any alignment padding
        let stack_size = layout.stack_top() - layout.stack_bottom();
        let heap_size = layout.heap_end() - layout.heap_start();
        let public_input_span = layout.public_input_end() - layout.public_input_start();
        let public_output_span = layout.public_output_end() - layout.public_output_start();
        let exit_code_size = nexus_common::constants::WORD_SIZE as u32;

        let static_memory_size: usize = 0x60; // arbitrary static memory contribution in bytes

        let expected_total = static_memory_size
            + stack_size as usize
            + heap_size as usize
            + public_input_span as usize
            + public_output_span as usize
            + exit_code_size as usize;

        let actual = layout.tracked_ram_size(static_memory_size);
        assert_eq!(actual, expected_total);
        assert!(heap_size > 0, "heap should be non-zero in this test");
    }

    #[test]
    fn tracked_ram_size_handles_zero_heap() {
        // Zero heap, non-zero stack
        let max_heap_size: u32 = 0x0;
        let max_stack_size: u32 = 0x300; // 768 bytes
        let public_input_size: u32 = 0x20; // 32 bytes (raw)
        let public_output_size: u32 = 0x40; // 64 bytes (raw)
        let program_size: u32 = 0x800; // 2048 bytes
        let ad_size: u32 = 0x0; // 0 bytes

        let layout = LinearMemoryLayout::try_new(
            None,
            max_heap_size,
            max_stack_size,
            public_input_size,
            public_output_size,
            program_size,
            ad_size,
        )
        .unwrap();

        let stack_size = layout.stack_top() - layout.stack_bottom();
        let heap_size = layout.heap_end() - layout.heap_start(); // should be 0
        let public_input_span = layout.public_input_end() - layout.public_input_start();
        let public_output_span = layout.public_output_end() - layout.public_output_start();
        let exit_code_size = nexus_common::constants::WORD_SIZE as u32;

        let static_memory_size: usize = 0x0;

        let expected_total = static_memory_size
            + stack_size as usize
            + heap_size as usize
            + public_input_span as usize
            + public_output_span as usize
            + exit_code_size as usize;

        let actual = layout.tracked_ram_size(static_memory_size);
        assert_eq!(actual, expected_total);
        assert_eq!(heap_size, 0);
    }
}
