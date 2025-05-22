use nexus_vm::trace::{Block, Trace};
use nexus_vm_prover_trace::program::ProgramStep;

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote<'a> {
    execution_trace: &'a [Block],
    num_steps: usize,
}

impl<'a> SideNote<'a> {
    pub fn new<'b: 'a>(trace: &'b impl Trace) -> Self {
        SideNote {
            execution_trace: trace.as_blocks_slice(),
            num_steps: trace.get_num_steps(),
        }
    }

    pub fn iter_program_steps(&self) -> impl Iterator<Item = ProgramStep<'a>> {
        self.execution_trace.iter().map(ProgramStep::from)
    }

    pub fn num_program_steps(&self) -> usize {
        self.num_steps
    }
}
