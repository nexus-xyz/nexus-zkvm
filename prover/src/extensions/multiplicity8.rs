// Multiplicity8 extension is a special case because it requires eight padding rows in order to fit the SIMD usage

use num_traits::{CheckedSub, Zero};
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
    chips::range_check::range8::Range8LookupElements, components::AllLookupElements,
    trace::sidenote::SideNote,
};

use super::{BuiltInExtension, FrameworkEvalExt};

/// A component for range check multiplicity
#[derive(Debug, Clone)]
pub struct Multiplicity8 {
    _private: (),
}

impl Multiplicity8 {
    pub(super) const fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct MultiplicityEval8 {
    lookup_elements: Range8LookupElements,
}

impl MultiplicityEval8 {
    const LOG_SIZE: u32 = LOG_N_LANES; // SIMD needs 16 rows to operate
}

impl Default for MultiplicityEval8 {
    fn default() -> Self {
        Self {
            lookup_elements: Range8LookupElements::dummy(),
        }
    }
}

/// A column with {0, ..., 7} and eight zero's
#[derive(Debug, Clone)]
pub struct RangeValues8;

impl RangeValues8 {
    pub const fn new(_log_size: u32) -> Self {
        Self {}
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: "preprocessed_range_values_8".to_owned(),
        }
    }
}

impl FrameworkEval for MultiplicityEval8 {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    // We don't need anything special about the eight additional zero's in the preprocessed column because
    // whatever the malicious prover can do with the additional padding rows, the malicious prover can do the
    // same using the non-padding row with zero.
    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let checked_value = RangeValues8::new(Self::LOG_SIZE);
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

impl FrameworkEvalExt for MultiplicityEval8 {
    const LOG_SIZE: u32 = Self::LOG_SIZE;

    fn new(lookup_elements: &AllLookupElements) -> Self {
        let lookup: &Range8LookupElements = lookup_elements.as_ref();
        Self {
            lookup_elements: lookup.clone(),
        }
    }
}

impl BuiltInExtension for Multiplicity8 {
    type Eval = MultiplicityEval8;

    fn generate_preprocessed_trace(
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::preprocessed_base_columns();
        let domain = CanonicCoset::new(Self::Eval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn preprocessed_trace_sizes() -> Vec<u32> {
        vec![Self::Eval::LOG_SIZE]
    }

    /// Contains only one column, representing the multiplicity
    ///
    /// The ordering of rows is the same as the ordering of the preprocessed value column.
    fn generate_original_trace(
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::base_columns(side_note);
        let domain = CanonicCoset::new(Self::Eval::LOG_SIZE).circle_domain();
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
        let lookup_element: &Range8LookupElements = lookup_elements.as_ref();
        let values = &Self::preprocessed_base_columns()[0];
        let base_cols = Self::base_columns(side_note);
        let mut logup_trace_gen = LogupTraceGenerator::new(Self::Eval::LOG_SIZE);

        // Subtract looked up values with the multiplicity
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1
            << (Self::Eval::LOG_SIZE
                .checked_sub(LOG_N_LANES)
                .expect("LOG_SIZE should be big enough for SIMD")))
        {
            let value = values.data[vec_row];
            let denom = lookup_element.combine(&[value]);
            let numerator = -base_cols[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
        logup_trace_gen.finalize_last()
    }
}

impl Multiplicity8 {
    fn num_padding() -> usize {
        (1 << LOG_N_LANES)
            .checked_sub(&8)
            .expect("Code assumes SIMD lanes should be at least 8")
    }
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let range_values = BaseColumn::from_iter(
            (0..8)
                .map(BaseField::from)
                .chain(std::iter::repeat(BaseField::zero()).take(Self::num_padding())),
        );
        vec![range_values]
    }
    fn base_columns(side_note: &SideNote) -> Vec<BaseColumn> {
        let multiplicities = BaseColumn::from_iter(
            side_note
                .range8
                .multiplicity
                .into_iter()
                .map(BaseField::from)
                .chain(std::iter::repeat(BaseField::zero()).take(Self::num_padding())),
        );
        vec![multiplicities]
    }
}
