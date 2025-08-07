//! Range256 multiplicities component optimized to subtract lookups in pairs.
//!
//! For simplicity, since ELEM_BITS = EXPAND_BITS = 4, 2 constant columns have been relabeled from (a_low, b_low)
//! to (a_low, a_high) and replaced with a single column `a`.

use num_traits::Zero;
use stwo::{
    core::{
        air::Component,
        channel::Blake2sChannel,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::TreeVec,
        poly::circle::CanonicCoset,
        ColumnVec,
    },
    prover::{
        backend::simd::{column::BaseColumn, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ComponentProver,
    },
};
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, EvalAtRow, FrameworkComponent, FrameworkEval,
    InfoEvaluator, RelationEntry, TraceLocationAllocator,
};

use nexus_vm_prover_trace::component::ComponentTrace;

use crate::{
    framework::MachineComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, LogupTraceBuilder, Range256LookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

pub const RANGE256: Range256Multiplicity = Range256Multiplicity;

pub struct Range256Multiplicity;

impl MachineComponent for Range256Multiplicity {
    fn max_constraint_log_degree_bound(&self, _log_size: u32) -> u32 {
        Self::log_size() + 1
    }

    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        RangeMultiplicityEval {
            lookup_elements: Range256LookupElements::dummy(),
        }
        .evaluate(InfoEvaluator::empty())
        .mask_offsets
        .as_cols_ref()
        .map_cols(|_| log_size)
    }

    fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32> {
        vec![log_size]
    }

    fn draw_lookup_elements(
        &self,
        lookup_elements: &mut AllLookupElements,
        channel: &mut Blake2sChannel,
    ) {
        <Range256LookupElements as ComponentLookupElements>::draw(lookup_elements, channel);
    }

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        _program: &ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let preprocessed_columns = Self::preprocessed_trace_columns();
        let domain = CanonicCoset::new(log_size).circle_domain();
        preprocessed_columns
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_component_trace(&self, side_note: &mut SideNote) -> ComponentTrace {
        let preprocessed_trace = Self::preprocessed_trace_columns();
        let original_trace = Self::original_trace_columns(side_note);
        ComponentTrace {
            log_size: Self::log_size(),
            preprocessed_trace,
            original_trace,
        }
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
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());
        let lookup_elements: &Range256LookupElements = lookup_elements.as_ref();

        let b = &component_trace.preprocessed_trace[0];

        for a in 0..256 {
            let mult = &component_trace.original_trace[a as usize];
            let a = BaseField::from(a);

            logup_trace_builder.add_to_relation_with(
                lookup_elements,
                [mult.into()],
                |[mult]| (-mult).into(),
                &[a.into(), b.into()],
            );
        }

        logup_trace_builder.finalize()
    }

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        _log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a> {
        let lookup_elements = Range256LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            RangeMultiplicityEval { lookup_elements },
            claimed_sum,
        ))
    }

    fn to_component<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        _log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component + 'a> {
        let lookup_elements = Range256LookupElements::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            RangeMultiplicityEval { lookup_elements },
            claimed_sum,
        ))
    }
}

struct RangeMultiplicityEval {
    lookup_elements: Range256LookupElements,
}

impl FrameworkEval for RangeMultiplicityEval {
    fn log_size(&self) -> u32 {
        Range256Multiplicity::log_size()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Range256Multiplicity::log_size() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let b = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "range_check_256_value".to_string(),
        });

        for a in 0u32..256 {
            let multiplicity = eval.next_trace_mask();
            let a = E::F::from(BaseField::from(a));

            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                (-multiplicity).into(),
                &[a, b.clone()],
            ));
        }

        eval.finalize_logup_in_pairs();
        eval
    }
}

impl Range256Multiplicity {
    fn log_size() -> u32 {
        8
    }

    fn preprocessed_trace_columns() -> Vec<BaseColumn> {
        let col = BaseColumn::from_iter((0..256).map(BaseField::from));
        vec![col]
    }

    fn original_trace_columns(side_note: &SideNote) -> Vec<BaseColumn> {
        let mut result = vec![];
        let range256_mults = &side_note.range_check.range256;

        for col in 0..=255 {
            let mut mults_col = vec![BaseField::zero(); 1 << 8];
            for ((_a, b), m) in range256_mults.range((col, 0)..=(col, 255)) {
                mults_col[*b as usize] = BaseField::from(*m);
            }

            result.push(BaseColumn::from_iter(mults_col))
        }

        result
    }
}
