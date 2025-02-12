//! # RISC-V Emulator Module
//!
//! This module provides the core functionality for the RISC-V emulator, including memory management,
//! execution, and I/O handling.
//!
//! ## Key Components
//!
//! - `Emulator`: A trait defining common methods for emulator implementations.
//! - `HarvardEmulator`: An implementation of the emulator using Harvard architecture.
//! - `LinearEmulator`: An implementation of the emulator using Linear architecture.
//! - `LinearMemoryLayout`: Defines the memory layout for the linear emulator.
//!
//! ## Memory Management
//!
//! The module provides structures and methods for managing different types of memory:
//! - Program memory (instructions)
//! - Initial memory (including public input, static ROM, and static RAM)
//! - Public output memory
//! - Associated data
//!
//! ## Usage
//!
//! ```rust
//! use nexus_vm::emulator::{Emulator, HarvardEmulator, LinearEmulator, LinearMemoryLayout};
//! use nexus_vm::elf::ElfFile;
//! use nexus_vm::error::VMError::VMExited;
//!
//! // Create a Harvard emulator
//! let elf_file = ElfFile::from_path("test/fib_10.elf").unwrap();
//! let mut harvard_emulator = HarvardEmulator::from_elf(&elf_file, &[], &[]);
//!
//! // Create a Linear emulator
//! let mut linear_emulator = LinearEmulator::from_elf(
//!     LinearMemoryLayout::default(),
//!     &[],
//!     &elf_file,
//!     &[],
//!     &[]
//! );
//!
//! // Execute the program, and check the exit code, 0 means success
//! assert_eq!(harvard_emulator.execute(true), Err(VMExited(0)));
//! assert_eq!(linear_emulator.execute(true), Err(VMExited(0)));
//!
//!
//! // Get the final state
//! let harvard_view = harvard_emulator.finalize();
//! let linear_view = linear_emulator.finalize();
//! ```
//!
//! This module provides a flexible and comprehensive framework for RISC-V emulation,
//! supporting both Harvard and Linear architectures (unified memory from Harvard architecture
//! with a single memory space, with added read and write protection), and offering detailed
//! visibility into the emulator's state and execution results.
mod executor;
mod layout;
mod memory_stats;
mod registry;

pub use executor::{Emulator, Executor, HarvardEmulator, LinearEmulator};
pub use layout::LinearMemoryLayout;

mod utils;
pub use utils::*;
