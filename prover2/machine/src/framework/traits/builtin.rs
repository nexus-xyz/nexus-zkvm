use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::SimdBackend,
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::{builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval};

use crate::{
    lookups::{AllLookupElements, ComponentLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

pub trait BuiltInComponent {
    /// Logarithmic bound for the maximum constraint degree.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

    /// Preprocessed trace column type.
    type PreprocessedColumn: PreprocessedAirColumn;

    /// Main (original) trace column type.
    type MainColumn: AirColumn;

    /// Lookups elements used by the component.
    type LookupElements: ComponentLookupElements;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program: &ProgramTraceRef,
    ) -> FinalizedTrace;

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace;

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    );
}
