//! Erased dyn-compatible version of the [`BuiltInComponent`] trait.

use stwo_prover::{
    constraint_framework::{FrameworkEval, InfoEvaluator, TraceLocationAllocator},
    core::{
        air::{Component, ComponentProver},
        backend::simd::SimdBackend,
        channel::Blake2sChannel,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::TreeVec,
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::component::ComponentTrace;

use super::builtin::BuiltInComponent;
use crate::{
    framework::eval::{BuiltInComponentEval, FrameworkComponent},
    lookups::{AllLookupElements, ComponentLookupElements},
    side_note::{program::ProgramTraceRef, SideNote},
};

#[allow(unused)] // TODO: remove with introduction of the first lookup relation
pub trait MachineComponent {
    /// Returns the log size of the evaluation domain.
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32;

    /// Returns mask offsets of the component's circuit.
    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>>;

    /// Returns the log_sizes of each preprocessed columns
    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32>;

    /// Inserts component's lookup elements into the mapping.
    ///
    /// This method should be infallible: all lookup elements are shared by multiple components.
    // TODO: support poseidon channel through enum
    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: &mut Blake2sChannel,
    );

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program: &ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace;

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a>;

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a>;
}

impl<C: BuiltInComponent> MachineComponent for C
where
    C: 'static + Sync,
    C::LookupElements: Sync + 'static,
{
    fn max_constraint_log_degree_bound(&self, log_size: u32) -> u32 {
        BuiltInComponentEval::<C>::max_constraint_log_degree_bound(log_size)
    }

    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        BuiltInComponentEval::<C> {
            component: self,
            log_size: 0,
            lookup_elements: C::LookupElements::dummy(),
        }
        .evaluate(InfoEvaluator::empty())
        .mask_offsets
        .as_cols_ref()
        .map_cols(|_| log_size)
    }

    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32> {
        vec![log_size; C::PreprocessedColumn::COLUMNS_NUM]
    }

    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: &mut Blake2sChannel,
    ) {
        C::LookupElements::draw(lookup_elements, channel);
    }

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        program: &ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let preprocessed_columns =
            <C as BuiltInComponent>::generate_preprocessed_trace(self, log_size, program);
        let domain = CanonicCoset::new(log_size).circle_domain();
        preprocessed_columns
            .cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace {
        let original_trace = <C as BuiltInComponent>::generate_main_trace(self, side_note);

        let log_size = original_trace.log_size;
        let preprocessed_trace = <C as BuiltInComponent>::generate_preprocessed_trace(
            self,
            log_size,
            &side_note.program,
        );

        ComponentTrace {
            log_size,
            preprocessed_trace: preprocessed_trace.cols,
            original_trace: original_trace.cols,
        }
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        <C as BuiltInComponent>::generate_interaction_trace(
            self,
            component_trace,
            side_note,
            lookup_elements,
        )
    }

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a> {
        let lookup_elements = C::LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            BuiltInComponentEval::<C> {
                component: self,
                log_size,
                lookup_elements,
            },
            claimed_sum,
        ))
    }

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a> {
        let lookup_elements = C::LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            BuiltInComponentEval::<C> {
                component: self,
                log_size,
                lookup_elements,
            },
            claimed_sum,
        ))
    }
}
