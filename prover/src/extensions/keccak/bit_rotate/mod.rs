//! Bit rotation lookup table.
//!
//! The table contains all results of shifting an 8-bit number left by r bits,  where r is in range [0; 8).
//! The first two columns of the preprocessed trace contain each combination of a byte and rotation r, next two
//! columns contain "high" part of the byte that will move to the left, and the remainder -- "low" byte.
//!
//! For instance, 0b11111111 with a bit shift 7 will have 0b01111111 as high byte and 0b1000000 as low byte.

use std::{collections::BTreeMap, simd::u32x16};

use stwo_prover::{
    constraint_framework::{
        logup::LogupTraceGenerator, preprocessed_columns::PreProcessedColumnId, EvalAtRow,
        FrameworkEval, Relation, RelationEntry,
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
    components::{lookups::KeccakBitRotateLookupElements, AllLookupElements},
    extensions::{BuiltInExtension, ComponentTrace, FrameworkEvalExt},
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

#[derive(Default)]
pub struct BitRotateAccumulator {
    counter: BTreeMap<u32, u32>,
}

impl BitRotateAccumulator {
    pub fn add_rotation(&mut self, input: u32x16, r: u32) {
        for &byte in input.as_array() {
            let offset = 8 * byte + r;
            *self.counter.entry(offset).or_default() += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BitRotateTable {
    pub(crate) _private: (),
}

pub(crate) struct BitRotateTableEval {
    lookup_elements: KeccakBitRotateLookupElements,
}

impl BitRotateTableEval {
    pub(crate) const LOG_SIZE: u32 = 8 + 3;
}

impl FrameworkEval for BitRotateTableEval {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        const PREPROCESSED_COLUMNS: &[&str] = &[
            "rotate_table_input_byte",
            "rotate_table_byte_shift",
            "rotate_table_bits_high",
            "rotate_table_bits_low",
        ];

        let preprocessed_columns: Vec<E::F> = PREPROCESSED_COLUMNS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();

        let multiplicity = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            (-multiplicity).into(),
            &preprocessed_columns,
        ));

        eval.finalize_logup();
        eval
    }
}

impl FrameworkEvalExt for BitRotateTableEval {
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        let lookup_elements: &KeccakBitRotateLookupElements = lookup_elements.as_ref();
        Self {
            lookup_elements: lookup_elements.clone(),
        }
    }

    fn dummy(log_size: u32) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        Self {
            lookup_elements: KeccakBitRotateLookupElements::dummy(),
        }
    }
}

impl BuiltInExtension for BitRotateTable {
    type Eval = BitRotateTableEval;

    fn generate_preprocessed_trace(
        &self,
        _: u32,
        _: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::preprocessed_base_columns();
        let domain = CanonicCoset::new(Self::Eval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_component_trace(
        &self,
        _log_size: u32,
        _program_trace_ref: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace {
        let accum = std::mem::take(&mut side_note.keccak.bit_rotate_accum);
        let preprocessed = Self::preprocessed_base_columns();
        let mult = Self::multiplicity_base_column(accum);

        ComponentTrace {
            log_size: Self::Eval::LOG_SIZE,
            preprocessed_trace: preprocessed,
            original_trace: vec![mult],
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
        let lookup_elements: &KeccakBitRotateLookupElements = lookup_elements.as_ref();
        let preprocessed_trace = &component_trace.preprocessed_trace;
        let multiplicity = &component_trace.original_trace[0];
        let mut logup_trace_gen = LogupTraceGenerator::new(Self::Eval::LOG_SIZE);

        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (Self::Eval::LOG_SIZE - LOG_N_LANES)) {
            let input = preprocessed_trace[0].data[vec_row];
            let shift = preprocessed_trace[1].data[vec_row];
            let bits_high = preprocessed_trace[2].data[vec_row];
            let bits_low = preprocessed_trace[3].data[vec_row];

            let denom = lookup_elements.combine(&[input, shift, bits_high, bits_low]);
            let numerator = -multiplicity.data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
        logup_trace_gen.finalize_last()
    }

    fn compute_log_size(&self, _: &SideNote) -> u32 {
        Self::Eval::LOG_SIZE
    }

    fn preprocessed_trace_sizes(_: u32) -> Vec<u32> {
        std::iter::repeat(Self::Eval::LOG_SIZE).take(4).collect()
    }
}

impl BitRotateTable {
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let range_iter = (0u32..256).flat_map(|byte| std::iter::repeat(byte).take(8));
        let shift_iter = (0u32..8)
            .clone()
            .cycle()
            .take(1 << BitRotateTableEval::LOG_SIZE);

        let in_column = BaseColumn::from_iter(range_iter.clone().map(BaseField::from));
        let shift_column = BaseColumn::from_iter(shift_iter.clone().map(BaseField::from));

        let bits_high = BaseColumn::from_iter(
            range_iter
                .clone()
                .zip(shift_iter.clone())
                .map(|(byte, shift)| BaseField::from(byte >> (8 - shift))),
        );
        let bits_low = BaseColumn::from_iter(
            range_iter
                .clone()
                .zip(shift_iter.clone())
                .map(|(byte, shift)| BaseField::from((byte << shift) & 255)),
        );

        vec![in_column, shift_column, bits_high, bits_low]
    }

    fn multiplicity_base_column(accum: BitRotateAccumulator) -> BaseColumn {
        BaseColumn::from_iter(
            (0..(1 << BitRotateTableEval::LOG_SIZE))
                .map(|i| accum.counter.get(&i).copied().unwrap_or_default().into()),
        )
    }
}
