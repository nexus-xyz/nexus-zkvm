use nexus_vm::{
    emulator::{
        InternalView, MemoryInitializationEntry, ProgramInfo, ProgramMemoryEntry,
        PublicOutputEntry, View,
    },
    trace::{Block, Trace},
};
use nexus_vm_prover_trace::program::ProgramStep;

use crate::components::BitwiseAccumulator;

use super::components::{ProgramMemorySideNote, ReadWriteMemorySideNote, RegisterMemorySideNote};

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote<'a> {
    execution_trace: &'a [Block],
    program_info: &'a ProgramInfo,
    init_memory: &'a [MemoryInitializationEntry],
    exit_code: &'a [PublicOutputEntry],
    output_memory: &'a [PublicOutputEntry],
    num_steps: usize,
    register_memory_side_note: RegisterMemorySideNote,
    read_write_memory_side_note: ReadWriteMemorySideNote,
    program_memory_side_note: ProgramMemorySideNote,
    pub(crate) bitwise_accum_and: BitwiseAccumulator,
    pub(crate) bitwise_accum_or: BitwiseAccumulator,
    pub(crate) bitwise_accum_xor: BitwiseAccumulator,
}

impl<'a> SideNote<'a> {
    pub fn new<'b: 'a>(trace: &'b impl Trace, view: &'a View) -> Self {
        SideNote {
            execution_trace: trace.as_blocks_slice(),
            program_info: view.get_program_memory(),
            init_memory: view.get_initial_memory(),
            exit_code: view.get_exit_code(),
            output_memory: view.get_public_output(),
            num_steps: trace.get_num_steps(),
            register_memory_side_note: Default::default(),
            read_write_memory_side_note: Default::default(),
            program_memory_side_note: Default::default(),
            bitwise_accum_and: BitwiseAccumulator::default(),
            bitwise_accum_or: BitwiseAccumulator::default(),
            bitwise_accum_xor: BitwiseAccumulator::default(),
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

    pub fn program_memory(&self) -> &[ProgramMemoryEntry] {
        &self.program_info.program
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

    pub fn program_memory_counter(&self) -> &ProgramMemorySideNote {
        &self.program_memory_side_note
    }

    pub fn program_memory_counter_mut(&mut self) -> &mut ProgramMemorySideNote {
        &mut self.program_memory_side_note
    }
}
