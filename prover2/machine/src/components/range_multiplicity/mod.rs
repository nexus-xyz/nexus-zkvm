//! Components that subtract final range check multiplicities.

use std::{collections::BTreeMap, marker::PhantomData};

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{
        preprocessed_columns::PreProcessedColumnId, EvalAtRow, FrameworkComponent, FrameworkEval,
        InfoEvaluator, RelationEntry, TraceLocationAllocator,
    },
    core::{
        air::{Component, ComponentProver},
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
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

use nexus_vm_prover_trace::component::ComponentTrace;

use crate::{
    framework::MachineComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, LogupTraceBuilder, Range128LookupElements,
        Range16LookupElements, Range32LookupElements, Range64LookupElements, Range8LookupElements,
        RegisteredLookupBound,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod range256;

// using [`BuiltInComponent`] trait causes a collision of preprocessed ids in generic implementation,
// because of this range-multiplicity implements the erased trait manually

pub struct RangeMultiplicity<const LOG_SIZE: u32, R> {
    _phantom: PhantomData<R>,
}

impl<const LOG_SIZE: u32, R> MachineComponent for RangeMultiplicity<LOG_SIZE, R>
where
    R: RegisteredLookupBound,
{
    fn max_constraint_log_degree_bound(&self, _log_size: u32) -> u32 {
        Self::log_size() + 1
    }

    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        RangeMultiplicityEval::<LOG_SIZE, R> {
            lookup_elements: R::dummy(),
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
        <R as ComponentLookupElements>::draw(lookup_elements, channel);
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
        let original_trace = Self::original_trace_columns(&side_note.range_check);
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
        let lookup_elements: &R = lookup_elements.as_ref();
        let values = &component_trace.preprocessed_trace[0];
        let mult = &component_trace.original_trace[0];

        logup_trace_builder.add_to_relation_with(
            lookup_elements,
            [mult.into()],
            |[mult]| (-mult).into(),
            &[values.into()],
        );

        logup_trace_builder.finalize()
    }

    fn to_component_prover<'a>(
        &'a self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        _log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend> + 'a> {
        let lookup_elements = R::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            RangeMultiplicityEval::<LOG_SIZE, R> { lookup_elements },
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
        let lookup_elements = R::get(lookup_elements);
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            RangeMultiplicityEval::<LOG_SIZE, R> { lookup_elements },
            claimed_sum,
        ))
    }
}

struct RangeMultiplicityEval<const LOG_SIZE: u32, R> {
    lookup_elements: R,
}

impl<const LOG_SIZE: u32, R> FrameworkEval for RangeMultiplicityEval<LOG_SIZE, R>
where
    R: RegisteredLookupBound,
{
    fn log_size(&self) -> u32 {
        RangeMultiplicity::<LOG_SIZE, R>::log_size()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        RangeMultiplicity::<LOG_SIZE, R>::log_size() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let lookup_elements = <R as RegisteredLookupBound>::as_relation_ref(&self.lookup_elements);
        let checked_value = eval.get_preprocessed_column(PreProcessedColumnId {
            id: format!("range_check_{}_value", 1 << LOG_SIZE),
        });
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-multiplicity).into(),
            &[checked_value],
        ));
        eval.finalize_logup();
        eval
    }
}

impl<const LOG_SIZE: u32, R> RangeMultiplicity<LOG_SIZE, R> {
    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn log_size() -> u32 {
        LOG_SIZE.max(LOG_N_LANES)
    }

    fn preprocessed_trace_columns() -> Vec<BaseColumn> {
        let log_size = Self::log_size();
        let mut col = vec![BaseField::zero(); 1 << log_size];

        for (i, val) in col[..1 << LOG_SIZE].iter_mut().enumerate() {
            *val = BaseField::from(i);
        }
        vec![BaseColumn::from_iter(col)]
    }

    fn original_trace_columns(accum: &RangeCheckAccumulator) -> Vec<BaseColumn> {
        let log_size = Self::log_size();
        let mut col = vec![BaseField::zero(); 1 << log_size];

        let mults: &BTreeMap<u8, u32> = match LOG_SIZE {
            3 => &accum.range8,
            4 => &accum.range16,
            5 => &accum.range32,
            6 => &accum.range64,
            7 => &accum.range128,
            _ => panic!("unsupported log size"),
        };

        for (row, mult) in mults {
            col[*row as usize] = BaseField::from(*mult);
        }
        vec![BaseColumn::from_iter(col)]
    }
}

pub const RANGE8: RangeMultiplicity<3, Range8LookupElements> = RangeMultiplicity::new();
pub const RANGE16: RangeMultiplicity<4, Range16LookupElements> = RangeMultiplicity::new();
pub const RANGE32: RangeMultiplicity<5, Range32LookupElements> = RangeMultiplicity::new();
pub const RANGE64: RangeMultiplicity<6, Range64LookupElements> = RangeMultiplicity::new();
pub const RANGE128: RangeMultiplicity<7, Range128LookupElements> = RangeMultiplicity::new();
pub use range256::RANGE256;
