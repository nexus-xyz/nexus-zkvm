use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{backend::simd::m31::PackedBaseField, channel::Channel},
};

use nexus_vm_prover_trace::component::FinalizedColumn;

use super::{private, AllLookupElements, ComponentLookupElements};
use crate::lookups::{LogupTraceBuilder, RegisteredLookupBound};

// lookup single value at a time
const RANGE_CHECK_LOOKUP_SIZE: usize = 1;

stwo_prover::relation!(Range8LookupElements, RANGE_CHECK_LOOKUP_SIZE);
stwo_prover::relation!(Range16LookupElements, RANGE_CHECK_LOOKUP_SIZE);
stwo_prover::relation!(Range32LookupElements, RANGE_CHECK_LOOKUP_SIZE);
stwo_prover::relation!(Range64LookupElements, RANGE_CHECK_LOOKUP_SIZE);
stwo_prover::relation!(Range128LookupElements, RANGE_CHECK_LOOKUP_SIZE);

#[derive(Clone, Debug, PartialEq)]
pub struct RangeCheckLookupElements {
    pub range8: Range8LookupElements,
    pub range16: Range16LookupElements,
    pub range32: Range32LookupElements,
    pub range64: Range64LookupElements,
    pub range128: Range128LookupElements,
    pub range256: Range256LookupElements,
}

impl private::Sealed for RangeCheckLookupElements {}

impl ComponentLookupElements for RangeCheckLookupElements {
    fn dummy() -> Self {
        Self {
            range8: Range8LookupElements::dummy(),
            range16: Range16LookupElements::dummy(),
            range32: Range32LookupElements::dummy(),
            range64: Range64LookupElements::dummy(),
            range128: Range128LookupElements::dummy(),
            range256: Range256LookupElements::dummy(),
        }
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        let range8: &Range8LookupElements = lookup_elements.as_ref();
        let range16: &Range16LookupElements = lookup_elements.as_ref();
        let range32: &Range32LookupElements = lookup_elements.as_ref();
        let range64: &Range64LookupElements = lookup_elements.as_ref();
        let range128: &Range128LookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();

        Self {
            range8: range8.to_owned(),
            range16: range16.to_owned(),
            range32: range32.to_owned(),
            range64: range64.to_owned(),
            range128: range128.to_owned(),
            range256: range256.to_owned(),
        }
    }

    fn draw(_: &mut AllLookupElements, _: &mut impl Channel) {
        // handled by a corresponding multiplicity components
    }
}

pub trait RangeLookupBound: RegisteredLookupBound {
    fn constrain<E: EvalAtRow>(&self, eval: &mut E, is_local_pad: E::F, value: E::F) {
        eval.add_to_relation(RelationEntry::new(
            self.as_relation_ref(),
            (E::F::one() - is_local_pad).into(),
            &[value],
        ));
    }

    fn generate_logup_col(
        &self,
        logup_trace_builder: &mut LogupTraceBuilder,
        is_local_pad: FinalizedColumn,
        value: FinalizedColumn,
    ) {
        logup_trace_builder.add_to_relation_with(
            self,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[value],
        );
    }
}

impl RangeLookupBound for Range8LookupElements {}
impl RangeLookupBound for Range16LookupElements {}
impl RangeLookupBound for Range32LookupElements {}
impl RangeLookupBound for Range64LookupElements {}
impl RangeLookupBound for Range128LookupElements {}

// range256 is optimized to lookup in pairs
const RANGE256_LOOKUP_SIZE: usize = 2;
stwo_prover::relation!(Range256LookupElements, RANGE256_LOOKUP_SIZE);

impl Range256LookupElements {
    pub fn constrain<E: EvalAtRow>(&self, eval: &mut E, is_local_pad: E::F, values: &[E::F]) {
        assert!(
            values.len() & 1 == 0,
            "range256 requires even number of values"
        );
        for pair in values.chunks(2) {
            eval.add_to_relation(RelationEntry::new(
                self,
                (E::F::one() - is_local_pad.clone()).into(),
                pair,
            ));
        }
    }

    pub fn generate_logup_col(
        &self,
        logup_trace_builder: &mut LogupTraceBuilder,
        is_local_pad: FinalizedColumn,
        values: &[FinalizedColumn],
    ) {
        assert!(
            values.len() & 1 == 0,
            "range256 requires even number of values"
        );

        for pair in values.chunks(2) {
            logup_trace_builder.add_to_relation_with(
                self,
                [is_local_pad.clone()],
                |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
                pair,
            );
        }
    }
}
