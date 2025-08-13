use nexus_vm::emulator::{
    InternalView, MemoryInitializationEntry, ProgramInfo, PublicOutputEntry, View,
};

/// Read-only view into the program’s initial memory state and the bytecode,
/// known to the verifier as a part of the preprocessed trace.
#[derive(Debug, Clone, Copy)]
pub struct ProgramTraceRef<'a> {
    /// Reference to the program memory.
    pub program_memory: &'a ProgramInfo,
    /// Slice of initial memory entries.
    pub init_memory: &'a [MemoryInitializationEntry],
    /// Slice of exit code output entries.
    pub exit_code: &'a [PublicOutputEntry],
    /// Slice of public output entries.
    pub public_output: &'a [PublicOutputEntry],
}

impl<'a> ProgramTraceRef<'a> {
    pub fn new(view: &'a View) -> Self {
        Self {
            program_memory: view.get_program_memory(),
            init_memory: view.get_ro_initial_memory(), // TODO: add public input and rw initial memory components
            exit_code: view.get_exit_code(),
            public_output: view.get_public_output(),
        }
    }
}
