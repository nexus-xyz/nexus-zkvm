use nexus_vm::emulator::{
    InternalView, MemoryInitializationEntry, ProgramInfo, PublicOutputEntry, View,
};

/// Read-only view into the program’s initial memory state and the bytecode,
/// known to the verifier as a part of the preprocessed trace.
#[derive(Debug, Clone, Copy)]
pub struct ProgramTraceRef<'a> {
    /// Reference to the program memory.
    pub program_memory: &'a ProgramInfo,
    /// Read-only section of memory.
    pub ro_memory: &'a [MemoryInitializationEntry],
    /// Public input section of memory.
    pub public_input: &'a [MemoryInitializationEntry],
    /// Static read-write memory initial state.
    pub static_memory: &'a [MemoryInitializationEntry],
    /// Slice of exit code output entries.
    pub exit_code: &'a [PublicOutputEntry],
    /// Slice of public output entries.
    pub public_output: &'a [PublicOutputEntry],
    /// Start of the private read-write memory.
    pub private_memory_start: u32,
    /// End of the private read-write memory.
    pub private_memory_end: u32,
}

impl<'a> ProgramTraceRef<'a> {
    pub fn new(view: &'a View) -> Self {
        let (memory_start, memory_end) = if let Some(layout) = view.view_memory_layout() {
            (layout.heap_start(), layout.stack_top())
        } else if cfg!(test) {
            (0, u32::MAX)
        } else {
            panic!("memory layout must be present")
        };
        Self {
            program_memory: view.get_program_memory(),
            ro_memory: view.get_ro_initial_memory(),
            public_input: view.get_public_input(),
            static_memory: view.get_rw_initial_memory(),
            exit_code: view.get_exit_code(),
            public_output: view.get_public_output(),
            private_memory_start: memory_start,
            private_memory_end: memory_end,
        }
    }
}
