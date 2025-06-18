use nexus_vm::{
    emulator::{InternalView, MemoryInitializationEntry, PublicOutputEntry, View},
    trace::{Block, Trace},
};
use nexus_vm_prover_trace::program::ProgramStep;

use super::components::{ReadWriteMemorySideNote, RegisterMemorySideNote};

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote<'a> {
    execution_trace: &'a [Block],
    init_memory: &'a [MemoryInitializationEntry],
    exit_code: &'a [PublicOutputEntry],
    output_memory: &'a [PublicOutputEntry],
    num_steps: usize,
    register_memory_side_note: RegisterMemorySideNote,
    read_write_memory_side_note: ReadWriteMemorySideNote,
}

impl<'a> SideNote<'a> {
    pub fn new<'b: 'a>(trace: &'b impl Trace, view: &'a View) -> Self {
        SideNote {
            execution_trace: trace.as_blocks_slice(),
            init_memory: view.get_initial_memory(),
            exit_code: view.get_exit_code(),
            output_memory: view.get_public_output(),
            num_steps: trace.get_num_steps(),
            register_memory_side_note: Default::default(),
            read_write_memory_side_note: Default::default(),
        }
    }

    pub fn init_memory(&self) -> &[MemoryInitializationEntry] {
        self.init_memory
    }

    pub fn exit_code(&self) -> &[PublicOutputEntry] {
        self.exit_code
    }

    pub fn output_memory(&self) -> &[PublicOutputEntry] {
        self.output_memory
    }

    pub fn iter_program_steps(&self) -> impl DoubleEndedIterator<Item = ProgramStep<'a>> {
        self.execution_trace.iter().map(ProgramStep::from)
    }

    pub fn num_program_steps(&self) -> usize {
        self.num_steps
    }

    pub fn register_memory(&self) -> &RegisterMemorySideNote {
        &self.register_memory_side_note
    }

    pub fn register_memory_mut(&mut self) -> &mut RegisterMemorySideNote {
        &mut self.register_memory_side_note
    }

    pub fn read_write_memory(&self) -> &ReadWriteMemorySideNote {
        &self.read_write_memory_side_note
    }

    pub fn read_write_memory_mut(&mut self) -> &mut ReadWriteMemorySideNote {
        &mut self.read_write_memory_side_note
    }
}
