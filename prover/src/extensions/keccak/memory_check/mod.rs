use stwo_prover::{
    constraint_framework::{EvalAtRow, FrameworkEval},
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use super::LANE_SIZE;
use crate::{
    components::{
        lookups::{KeccakStateLookupElements, LoadStoreLookupElements},
        AllLookupElements,
    },
    extensions::{BuiltInExtension, ComponentTrace, FrameworkEvalExt},
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

mod constraints;
mod trace;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermutationMemoryCheck {
    pub(crate) _private: (),
}

pub(crate) struct PermutationMemoryCheckEval {
    log_size: u32,
    state_lookup_elements: KeccakStateLookupElements,
    memory_lookup_elements: LoadStoreLookupElements,
}

impl PermutationMemoryCheckEval {
    const STATE_SIZE: usize = 25 * LANE_SIZE;
}

impl FrameworkEval for PermutationMemoryCheckEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        constraints::PermutationMemoryCheckEval {
            eval,
            state_lookup_elements: &self.state_lookup_elements,
            memory_lookup_elements: &self.memory_lookup_elements,
        }
        .eval()
    }
}

impl FrameworkEvalExt for PermutationMemoryCheckEval {
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self {
        let state_lookup_elements: &KeccakStateLookupElements = lookup_elements.as_ref();
        let memory_lookup_elements: &LoadStoreLookupElements = lookup_elements.as_ref();
        Self {
            log_size,
            state_lookup_elements: state_lookup_elements.clone(),
            memory_lookup_elements: memory_lookup_elements.clone(),
        }
    }

    fn dummy(log_size: u32) -> Self {
        Self {
            log_size,
            state_lookup_elements: KeccakStateLookupElements::dummy(),
            memory_lookup_elements: LoadStoreLookupElements::dummy(),
        }
    }
}

impl BuiltInExtension for PermutationMemoryCheck {
    type Eval = PermutationMemoryCheckEval;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        _: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_col = trace::preprocessed_is_last_column(log_size);
        let domain = CanonicCoset::new(log_size).circle_domain();
        vec![CircleEvaluation::new(domain, base_col)]
    }

    fn generate_component_trace(
        &self,
        log_size: u32,
        _program_trace_ref: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace {
        trace::generate_keccak_mem_check_trace(log_size, side_note)
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let state_lookup_elements: &KeccakStateLookupElements = lookup_elements.as_ref();
        let memory_lookups: &LoadStoreLookupElements = lookup_elements.as_ref();
        trace::MemoryCheckLogUpGenerator {
            component_trace: &component_trace,
        }
        .interaction_trace(state_lookup_elements, memory_lookups)
    }

    fn compute_log_size(&self, side_note: &SideNote) -> u32 {
        let num_inputs = side_note.keccak.inputs.len();
        let log_size = num_inputs.next_power_of_two().ilog2();

        log_size.max(LOG_N_LANES)
    }

    fn preprocessed_trace_sizes(log_size: u32) -> Vec<u32> {
        vec![log_size]
    }
}
