## RISC-V Virtual Machine Project Structure

Directory structure of `vm` crate:

```
├── Cargo.toml
├── README.md
├── build.rs
├── src
│   ├── cpu
│   │   ├── instructions
│   │   │   ├── README.md
│   │   │   ├── i
│   │   │   │   ├── add.rs
│   │   │   │   ├── and.rs
│   │   │   │   ├── auipc.rs
│   │   │   │   ├── beq.rs
│   │   │   │   ├── bge.rs
│   │   │   │   ├── blt.rs
│   │   │   │   ├── bne.rs
│   │   │   │   ├── jal.rs
│   │   │   │   ├── lb.rs
│   │   │   │   ├── lh.rs
│   │   │   │   ├── lui.rs
│   │   │   │   ├── lw.rs
│   │   │   │   ├── mod.rs
│   │   │   │   ├── or.rs
│   │   │   │   ├── sb.rs
│   │   │   │   ├── sh.rs
│   │   │   │   ├── sll.rs
│   │   │   │   ├── slt.rs
│   │   │   │   ├── sra.rs
│   │   │   │   ├── srl.rs
│   │   │   │   ├── sub.rs
│   │   │   │   ├── sw.rs
│   │   │   │   └── xor.rs
│   │   │   ├── m
│   │   │   │   ├── div.rs
│   │   │   │   ├── mod.rs
│   │   │   │   ├── mul.rs
│   │   │   │   ├── mulh.rs
│   │   │   │   └── rem.rs
│   │   │   ├── macros.rs
│   │   │   └── mod.rs
│   │   ├── mod.rs
│   │   ├── registerfile.rs
│   │   └── state.rs
│   ├── elf
│   │   ├── error.rs
│   │   ├── loader.rs
│   │   ├── mod.rs
│   │   └── parser.rs
│   ├── emulator
│   │   ├── executor.rs
│   │   ├── layout.rs
│   │   ├── memory_stats.rs
│   │   ├── mod.rs
│   │   ├── registry.rs
│   │   └── utils.rs
│   ├── error.rs
│   ├── lib.rs
│   ├── memory
│   │   ├── fixed.rs
│   │   ├── mod.rs
│   │   ├── unified.rs
│   │   └── variable.rs
│   ├── riscv
│   │   ├── decoder.rs
│   │   ├── instructions
│   │   │   ├── README.md
│   │   │   ├── basic_block.rs
│   │   │   ├── instruction.rs
│   │   │   ├── macros.rs
│   │   │   └── mod.rs
│   │   └── mod.rs
│   ├── system
│   │   ├── mod.rs
│   │   └── syscall.rs
│   └── trace.rs
└── test
    ├── fib_10.elf
    └── fib_10_no_precompiles.elf
```

The project is organized into several key modules:
1. `src/elf/`: ELF (Executable and Linkable Format) handling

   This module is crucial as it provides the initial program state for the VM, setting up memory and instructions for execution. It ensures proper parsing and validation of ELF files, handling various sections and segments, and extracting necessary information for the emulator to function correctly.

   Key structures:
   - `ElfFile`: Represents a parsed ELF file, containing:
     - Instructions (as 32-bit words)
     - Program entry point and base address
     - Read-only (ROM) and read-write (RAM) memory images
     - Nexus-specific metadata
   - `ParsedElfData`: Contains parsed ELF data including instructions, memory images, and metadata

   Features:
   - Supports little-endian RISC-V 32-bit executables
   - Distinguishes between different types of memory: instruction, read-only data, writable data, and metadata
   - Provides utilities for parsing and validating ELF headers, segments, and sections
   - Implements custom parsing for Nexus-specific precompile metadata

   Submodules:
   - `loader.rs`: Loads and parses RISC-V 32-bit ELF files
     - Implements Harvard architecture (separate instruction and data memory)
     - Supports loading from files or in-memory bytes
     - Extracts program instructions, entry point, base address, and initial memory images
   - `parser.rs`: Low-level ELF file parsing and validation
     - Validates ELF headers for RISC-V 32-bit executables
     - Parses segment information and extracts executable content
     - Handles allowed sections: `.text, .data, .sdata, .rodata, .init, .fini, .bss, .sbss, .got`
     - Supports custom metadata section: `.note.nexus-precompiles`
     - Parses precompile metadata from ELF symbols
   - `error.rs`: ELF-specific error handling

2. `src/riscv/`: RISC-V architecture specific components

   This module bridges the gap between raw binary data from the ELF files and the higher-level
   program representation used by the VM. It's crucial for instruction-level analysis,
   control flow graph construction, and optimization in the RISC-V emulator.

   Key structures and types:
   - `Instruction`: Represents a decoded RISC-V instruction
   - `BasicBlock`: Represents a sequence of instructions without intermediate branches
   - `BasicBlockProgram`: Represents an entire program as a collection of basic blocks
   - `InstructionDecoder`: Implements the `InstructionProcessor` trait for decoding instructions

   Features:
   - Supports decoding of standard RISC-V instructions and custom dynamic instructions
   - Organizes instructions into basic blocks for efficient analysis and execution
   - Provides utilities for instruction encoding, decoding, and display
   - Implements comprehensive error handling for invalid or unimplemented instructions

   Submodules:
   - `decoder.rs`: Decodes RISC-V instructions and organizes them into basic blocks
     - Provides `decode_instruction`, `decode_instructions`, and `decode_until_end_of_a_block` functions
     - Supports decoding of custom dynamic instructions (R-type, S-type, and I-type)
     - Implements efficient instruction parsing using bit manipulation
   - `instructions/`: Defines RISC-V instruction structures and utilities
     - `basic_block.rs`: Represents a sequence of instructions (basic block)
       - Provides methods for encoding, decoding, and displaying basic blocks
     - `instruction.rs`: Defines the unified `Instruction` struct for all instruction types
       - Implements `InstructionDecoder` for processing various RISC-V instruction formats
       - Supports RV32IM instruction set

3. `src/memory/`: Advanced Memory Management System

   This module implements a sophisticated memory management system with support for different memory types and access modes.
   It also provides a robust and flexible memory management system, suitable for
   emulating complex memory layouts and access patterns in the RISC-V emulator. It
   offers fine-grained control over memory access and efficient mechanisms for
   handling different memory types within a unified interface.

   Key Components:
   - `FixedMemory<M>`: Represents fixed-size memory with a specific access mode
   - `VariableMemory<M>`: Represents variable-size memory with a specific access mode
   - `UnifiedMemory`: Manages multiple memory regions with different characteristics
   - `MemoryProcessor`: Trait implemented by memory types for read/write operations

   Features:
   - Flexible memory configurations with different access modes and address ranges
   - Efficient memory access and management for both fixed and variable memory types
   - Debug and display formatting for easy visualization of memory contents
   - Support for byte, halfword, and word-sized operations with alignment checks

   Submodules:
   - `variable.rs`: Implements variable-size memory regions
     - Supports dynamic memory allocation, only allocating for addresses that have been written to
     - Implements Read-Only (RO), Write-Only (WO), Read-Write (RW) memory types
     - Provides efficient lookups and insertions using `BTreeMap` as underlying storage
     - Supports reading contiguous memory segments
   - `fixed.rs`: Implements fixed-size memory regions
     - Supports Read-Only (RO), Write-Only (WO), Read-Write (RW), and No-Access (NA) memory types
     - Provides byte, halfword, and word-sized read/write operations with alignment checks
     - Includes methods for creating memory from vectors or byte slices
   - `unified.rs`: Provides a unified memory interface
     - Combines fixed and variable memory types into a single, coherent memory system
     - Supports multiple memory regions with different access modes
     - Allows adding fixed memory regions with specific base addresses and sizes
     - Implements a fallback variable memory for addresses not covered by fixed regions

4. `src/cpu/`: Central Processing Unit (CPU) Emulation

   This module provides a comprehensive emulation of a RISC-V CPU, including
   state management, register operations, and instruction execution. It forms
   the core of the instruction execution pipeline in the RISC-V emulator.

   Key Features:
   - Accurate emulation of RISC-V CPU state and behavior
   - Support for both base integer (RV32I) and multiply (RV32M) instruction sets
   - Efficient register management with zero register handling
   - Debug-friendly register state display
   - Modular instruction implementation structure

   Submodules:
   - `state.rs`: Core CPU state management
     - `Cpu`: Represents the entire CPU state, including:
       - General purpose 32-bit registers
       - Program counter (PC)
       - Cycle counter
       - CPU state snapshot for the current block
     - Implements the `Processor` trait for register and PC access
   - `registerfile.rs`: Manages CPU registers
     - `RegisterFile`: Manages the state of 32 general-purpose registers
       - Implements zero register (x0) behavior
       - Provides read and write operations for registers
       - Implements `Display` for pretty-printing register states
   - `instructions/`: Implements CPU behaviors for RISC-V instructions
     - Includes implementations for RV32I Base Integer Instructions
     - Includes implementations for RV32M Multiply extension
     - Defines `InstructionResult` type for instruction execution outcomes
     - Contains macro implementations for instruction handling

5. `src/system/`: Handles system-level operations

   This module forms a crucial part of the emulator, bridging the gap between
   user-level code and system-level operations, and providing essential
   functionality for I/O, program termination, and performance profiling.

   Key Features:
   - Flexible syscall system supporting both standard and custom operations
   - Clear separation of concerns in syscall execution (decode, execute, memory ops, CPU write-back)
   - Support for profiling and debugging (CycleCount syscall)
   - Handling of private input for privacy-preserving computations
   - Memory layout modifications for stack and heap management
   - Extensible design allowing easy addition of new syscalls

   Submodules:
   - `syscall.rs`: Implements system calls for the RISC-V emulator
     - Implements `SyscallInstruction` struct to represent and execute syscalls:
       - Decodes syscall instructions from CPU state
       - Executes various syscalls:
         - `Write`: Output data to stdout (file descriptor 1)
         - `Exit`: Terminate program with specified error code
         - `CycleCount`: Profile function execution time
         - `ReadFromPrivateInput`: Read data from a private input tape
         - `OverwriteStackPointer`: Modify stack pointer based on memory layout
         - `OverwriteHeapPointer`: Modify heap pointer based on memory layout
       - Handles `memory interactions` for syscalls
       - `Writes back` results to CPU registers
     - Provides error handling for invalid or unimplemented syscalls
     - Supports different behavior for first and second pass execution
     - Includes comprehensive unit tests for syscall functionality

6. `src/emulator/`: Core emulation logic

   This module forms the core of the RISC-V emulator, providing a flexible and
   efficient framework for instruction execution, memory management, and
   emulator state analysis.

   Key Features:
   - Support for both Harvard and Linear (unified memory from Harvard architecture with a single memory space, with added read and write protection) architectures
   - Flexible memory management and layout optimization
   - Extensible instruction set with support for custom instructions
   - Comprehensive emulator state capture and analysis
   - Debug logging and performance profiling capabilities
   - Efficient basic block caching and execution

   Submodules:
   - `executor.rs`: Central component for RISC-V instruction execution
     - Defines `Executor` struct: Manages the core execution components
     - Implements `HarvardEmulator` and `LinearEmulator` for different memory architectures
     - Provides `Emulator` trait with common methods for both emulator types
     - Supports basic block execution and caching for improved performance
     - Handles system calls, custom instructions, and various memory types
     - Implements cycle counting, profiling, and debug logging
   - `layout.rs`: Defines memory layout for the RISC-V emulator
     - Implements `LinearMemoryLayout` struct for managing different memory regions
     - Provides methods for configuring and validating memory layouts
     - Supports various memory segments: registers, program, input/output, heap, stack, etc.
   - `memory_stats.rs`: Tracks and optimizes memory usage
     - Implements `MemoryStats` struct for tracking memory access statistics
     - Provides functionality to create optimized memory layouts based on usage patterns
   - `registry.rs`: Manages instruction execution functions
     - Implements `InstructionExecutorRegistry` for mapping opcodes to execution functions
     - Supports built-in RISC-V instructions and custom/special instructions
     - Provides extensibility for adding new opcodes at runtime
   - `mod.rs`: Defines the public interface for the emulator module
     - Exposes key structs and traits: `Emulator`, `HarvardEmulator`, `LinearEmulator`, `View`
     - Provides utilities for I/O handling and emulator state management


## Module Interactions

The RISC-V emulator is designed with a modular architecture, allowing for clear separation of concerns and efficient interaction between components. Here's an overview of how the key modules interact:

1. ELF Loading and Parsing:
   - The `elf::loader` module parses the ELF file, extracting program data, instructions, and memory images.
   - It populates the `ElfFile` struct with this information, which serves as the initial state for the emulator.

2. Instruction Decoding:
   - The `riscv::decoder` module takes raw instruction data from the `ElfFile` and decodes it into `Instruction` objects.
   - It also organizes instructions into basic blocks for efficient execution.

3. Memory Management:
   - The `memory` module provides a unified interface for different memory types (`fixed`, `variable`) and access modes (`RO`, `WO`, `RW`, `NA`).
   - Both `HarvardEmulator` and `LinearEmulator` in `emulator::executor` use this module to manage program memory, data memory, and I/O operations.

4. CPU State Management:
   - The `cpu` module maintains the CPU state, including registers and the program counter.
   - The `emulator::executor` interacts with this module to update CPU state during instruction execution.

5. Instruction Execution:
   - The `emulator::executor` module is the central component that orchestrates the execution process:
     - It retrieves instructions and memory images from the `ElfFile`.
     - Uses the `riscv::decoder` to interpret instructions.
     - Employs a basic block cache for optimized execution.
     - Executes instructions, updating the `cpu::Cpu` state and performing memory operations via the `memory` module.
     - Handles system calls by interfacing with the `system::syscall` module.

6. System Calls:
   - The `system::syscall` module handles system-level operations.
   - It's invoked by the `emulator::executor` when a syscall instruction is encountered.
   - Interacts with the `cpu` module to access and modify CPU state, and with the `memory` module for I/O operations.

7. Memory Layout and Optimization:
   - The `emulator::layout` module defines the memory layout used by the `LinearEmulator`.
   - The `emulator::memory_stats` module tracks memory usage and helps optimize the memory layout based on runtime behavior.

8. Instruction Registry:
   - The `emulator::registry` module manages the mapping between opcodes and their execution functions.
   - It allows for runtime extension of the instruction set, including custom instructions.

9. Emulator State Capture:
   - The `emulator::mod` module provides the `View` struct, which captures the final state of the emulator after execution.
   - This allows for analysis and debugging of the emulated program's behavior.

This architecture facilitates easier maintenance, testing, and future enhancements to the RISC-V emulator.
