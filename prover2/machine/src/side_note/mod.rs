use nexus_vm::{
    emulator::View,
    trace::{Block, Trace},
};
use nexus_vm_prover_trace::program::ProgramStep;

/// Accumulators for bitwise instructions lookups.
pub mod bitwise;
/// Memory-checking side notes.
pub mod memory;
/// Bytecode and the initial memory state.
pub mod program;
/// Range checks accumulators
pub mod range_check;

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote<'a> {
    execution_trace: &'a [Block],
    num_steps: usize,
    pub(crate) program: program::ProgramTraceRef<'a>,
    pub(crate) memory: memory::MemorySideNote,
    pub(crate) bitwise: bitwise::BitwiseAccumulators,
    pub(crate) range_check: range_check::RangeCheckAccumulator,
}

impl<'a> SideNote<'a> {
    pub fn new<'b: 'a>(trace: &'b impl Trace, view: &'a View) -> Self {
        SideNote {
            execution_trace: trace.as_blocks_slice(),
            num_steps: trace.get_num_steps(),
            program: program::ProgramTraceRef::new(view),
            memory: Default::default(),
            bitwise: Default::default(),
            range_check: Default::default(),
        }
    }

    pub fn iter_program_steps(&self) -> impl DoubleEndedIterator<Item = ProgramStep<'a>> {
        self.execution_trace.iter().map(ProgramStep::from)
    }

    pub fn num_program_steps(&self) -> usize {
        self.num_steps
    }
}
