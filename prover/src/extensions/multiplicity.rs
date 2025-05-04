use stwo_prover::{
    constraint_framework::{
        logup::LogupTraceGenerator, preprocessed_columns::PreProcessedColumnId, FrameworkEval,
        Relation, RelationEntry,
    },
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            qm31::PackedSecureField,
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use crate::{
    chips::range_check::{
        range128::Range128LookupElements, range16::Range16LookupElements,
        range256::Range256LookupElements, range32::Range32LookupElements,
    },
    components::{AllLookupElements, RegisteredLookupBound},
    trace::sidenote::{RangeCheckSideNote, RangeCheckSideNoteGetter, SideNote},
};

use super::{BuiltInExtension, FrameworkEvalExt};

/// A component for range check multiplicity
///
/// LEN is the size of the multiplicity table
/// L is the lookup challenge type for a Relation
#[derive(Debug, Clone)]
pub struct Multiplicity<const LEN: usize, L> {
    _phantom: std::marker::PhantomData<L>,
}

impl<const LEN: usize, L> Multiplicity<LEN, L> {
    pub(super) const fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

pub(crate) struct MultiplicityEval<const LEN: usize, L> {
    lookup_elements: L,
}

impl<const LEN: usize, L> MultiplicityEval<LEN, L> {
    const LOG_SIZE: u32 = {
        let log_size = LEN.ilog2();
        assert!(1 << log_size == LEN, "LEN must be a power of 2");
        log_size
    };
}

impl<L: RegisteredLookupBound, const LEN: usize> Default for MultiplicityEval<LEN, L> {
    fn default() -> Self {
        Self {
            lookup_elements: L::dummy(),
        }
    }
}

/// A column with {0, ..., LEN - 1} when LEN is a power of 2
#[derive(Debug, Clone)]
pub struct RangeValues<const LEN: usize>;

impl<const LEN: usize> RangeValues<LEN> {
    pub const fn new(_log_size: u32) -> Self {
        Self {}
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!("preprocessed_range_values_{LEN}"),
        }
    }
}

impl<const LEN: usize, L: RegisteredLookupBound> FrameworkEval for MultiplicityEval<LEN, L> {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let lookup_elements = <L as RegisteredLookupBound>::as_relation_ref(&self.lookup_elements);
        let checked_value = RangeValues::<LEN>::new(Self::LOG_SIZE);
        let checked_value = eval.get_preprocessed_column(checked_value.id());
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

impl<const LEN: usize, L: RegisteredLookupBound> FrameworkEvalExt for MultiplicityEval<LEN, L> {
    const LOG_SIZE: u32 = Self::LOG_SIZE;

    fn new(lookup_elements: &AllLookupElements) -> Self {
        let lookup: &L = lookup_elements.as_ref();
        Self {
            lookup_elements: lookup.clone(),
        }
    }
}

impl<const LEN: usize, L: RegisteredLookupBound> BuiltInExtension for Multiplicity<LEN, L>
where
    MultiplicityEval<LEN, L>: FrameworkEvalExt,
    SideNote: RangeCheckSideNoteGetter<LEN>,
    AllLookupElements: AsRef<L>,
    L: Relation<PackedBaseField, PackedSecureField>,
{
    type Eval = MultiplicityEval<LEN, L>;

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
        let lookup_element: &L = lookup_elements.as_ref();
        let values = &Self::preprocessed_base_columns()[0];
        let base_cols = Self::base_columns(side_note);
        let mut logup_trace_gen = LogupTraceGenerator::new(Self::Eval::LOG_SIZE);

        // Subtract looked up values with the multiplicity
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (Self::Eval::LOG_SIZE - LOG_N_LANES)) {
            let value = values.data[vec_row];
            let denom = lookup_element.combine(&[value]);
            let numerator = -base_cols[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
        logup_trace_gen.finalize_last()
    }
}

impl<const LEN: usize, L> Multiplicity<LEN, L> {
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let range_values = BaseColumn::from_iter((0..LEN).map(BaseField::from));
        vec![range_values]
    }
    fn base_columns(side_note: &SideNote) -> Vec<BaseColumn>
    where
        SideNote: RangeCheckSideNoteGetter<LEN>,
    {
        let range_check_side_note: &RangeCheckSideNote<LEN> = side_note.get_range_check_side_note();
        let multiplicities = BaseColumn::from_iter(
            range_check_side_note
                .multiplicity
                .into_iter()
                .map(BaseField::from),
        );
        vec![multiplicities]
    }
}

pub(crate) type Multiplicity16 = Multiplicity<16, Range16LookupElements>;
pub(crate) type Multiplicity32 = Multiplicity<32, Range32LookupElements>;
pub(crate) type Multiplicity128 = Multiplicity<128, Range128LookupElements>;
pub(crate) type Multiplicity256 = Multiplicity<256, Range256LookupElements>;
