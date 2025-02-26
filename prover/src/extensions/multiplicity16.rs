use stwo_prover::{
    constraint_framework::{
        logup::LogupTraceGenerator, preprocessed_columns::PreProcessedColumnId, FrameworkEval,
        Relation, RelationEntry,
    },
    core::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use crate::{
    chips::range_check::range16::Range16LookupElements, components::AllLookupElements,
    trace::sidenote::SideNote,
};

use super::{BuiltInExtension, FrameworkEvalExt};

/// A component for range check multiplicity
#[derive(Debug, Clone)]
pub struct Multiplicity16 {
    _private: (),
}

impl Multiplicity16 {
    pub(super) const fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct Multiplicity16Eval {
    lookup_elements: Range16LookupElements,
}

impl Default for Multiplicity16Eval {
    fn default() -> Self {
        Self {
            lookup_elements: Range16LookupElements::dummy(),
        }
    }
}

impl Multiplicity16Eval {
    // 16 multiplicities are considered, so 2^4 = 16 rows are needed.
    const LOG_SIZE: u32 = 4;
}

/// A column with {0, ..., 15}
#[derive(Debug, Clone)]
pub struct Range16;

impl Range16 {
    pub const fn new(_log_size: u32) -> Self {
        Self {}
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!("preprocessed_range_16_{}", Multiplicity16Eval::LOG_SIZE),
        }
    }
}

impl FrameworkEval for Multiplicity16Eval {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let checked_value = Range16::new(Multiplicity16Eval::LOG_SIZE);
        let checked_value = eval.get_preprocessed_column(checked_value.id());
        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            (-multiplicity).into(),
            &[checked_value],
        ));
        eval.finalize_logup();
        eval
    }
}

impl FrameworkEvalExt for Multiplicity16Eval {
    const LOG_SIZE: u32 = Multiplicity16Eval::LOG_SIZE;

    fn new(lookup_elements: &AllLookupElements) -> Self {
        let range16_lookup_elements: &Range16LookupElements = lookup_elements.as_ref();
        Self {
            lookup_elements: range16_lookup_elements.clone(),
        }
    }
}

impl BuiltInExtension for Multiplicity16 {
    type Eval = Multiplicity16Eval;

    fn generate_preprocessed_trace(
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::preprocessed_base_columns();
        let domain = CanonicCoset::new(Multiplicity16Eval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn preprocessed_trace_sizes() -> Vec<u32> {
        vec![Multiplicity16Eval::LOG_SIZE]
    }

    /// Contains only one column, representing the multiplicity
    ///
    /// The ordering of rows is the same as the ordering of the preprocessed value column.
    fn generate_original_trace(
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::base_columns(side_note);
        let domain = CanonicCoset::new(Multiplicity16Eval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_interaction_trace(
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let lookup_element: &Range16LookupElements = lookup_elements.as_ref();
        let values = &Self::preprocessed_base_columns()[0];
        let base_cols = Self::base_columns(side_note);
        let mut logup_trace_gen = LogupTraceGenerator::new(Multiplicity16Eval::LOG_SIZE);

        // Subtract looked up values with the multiplicity
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (Multiplicity16Eval::LOG_SIZE - LOG_N_LANES)) {
            let value = values.data[vec_row];
            let denom = lookup_element.combine(&[value]);
            let numerator = -base_cols[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
        logup_trace_gen.finalize_last()
    }
}

impl Multiplicity16 {
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let range16 = BaseColumn::from_iter((0..16).map(BaseField::from));
        vec![range16]
    }
    fn base_columns(side_note: &SideNote) -> Vec<BaseColumn> {
        let range16 = BaseColumn::from_iter(
            side_note
                .range16
                .multiplicity
                .into_iter()
                .map(BaseField::from),
        );
        vec![range16]
    }
}
