use nexus_vm::trace::{Block, Trace};
use nexus_vm_prover_trace::program::ProgramStep;

use super::components::RegisterMemorySideNote;

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote<'a> {
    execution_trace: &'a [Block],
    num_steps: usize,
    register_memory_side_note: RegisterMemorySideNote,
}

impl<'a> SideNote<'a> {
    pub fn new<'b: 'a>(trace: &'b impl Trace) -> Self {
        SideNote {
            execution_trace: trace.as_blocks_slice(),
            num_steps: trace.get_num_steps(),
            register_memory_side_note: Default::default(),
        }
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
}
