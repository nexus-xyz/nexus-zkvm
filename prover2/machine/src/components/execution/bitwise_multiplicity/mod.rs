//! Lookup table component for subtracting bitwise operations final multiplicities.

use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{column::BaseColumn, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm_prover_trace::{
    builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval, original_base_column,
    preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    components::execution::bitwise::{AND_LOOKUP_IDX, OR_LOOKUP_IDX, XOR_LOOKUP_IDX},
    framework::BuiltInComponent,
    lookups::{AllLookupElements, BitwiseInstrLookupElements, LogupTraceBuilder},
    side_note::SideNote,
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub struct BitwiseMultiplicity;

impl BitwiseMultiplicity {
    const NUM_BITS: u32 = 4;
    const LOG_SIZE: u32 = Self::NUM_BITS * 2;
}

impl BuiltInComponent for BitwiseMultiplicity {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = BitwiseInstrLookupElements;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let column_b =
            (0u8..1 << Self::NUM_BITS).flat_map(|i| std::iter::repeat_n(i, 1 << Self::NUM_BITS));
        let column_c = (0u8..1 << Self::NUM_BITS).cycle().take(1 << Self::LOG_SIZE);
        let range_iter = column_b.clone().zip(column_c.clone());

        let column_b = BaseColumn::from_iter(column_b.map(|i| BaseField::from(i as u32)));
        let column_c = BaseColumn::from_iter(column_c.map(|i| BaseField::from(i as u32)));
        let column_and =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b & c).into()));
        let column_or =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b | c).into()));
        let column_xor =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b ^ c).into()));

        FinalizedTrace {
            cols: vec![column_b, column_c, column_and, column_or, column_xor],
            log_size: Self::LOG_SIZE,
        }
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let multiplicity_and = side_note.bitwise_accum_and.multiplicities();
        let multiplicity_or = side_note.bitwise_accum_or.multiplicities();
        let multiplicity_xor = side_note.bitwise_accum_xor.multiplicities();

        let range = 0..=255;
        let multiplicity_and = BaseColumn::from_iter(
            range
                .clone()
                .map(|i| multiplicity_and.get(&i).copied().unwrap_or_default().into()),
        );
        let multiplicity_or = BaseColumn::from_iter(
            range
                .clone()
                .map(|i| multiplicity_or.get(&i).copied().unwrap_or_default().into()),
        );
        let multiplicity_xor = BaseColumn::from_iter(
            range.map(|i| multiplicity_xor.get(&i).copied().unwrap_or_default().into()),
        );
        FinalizedTrace {
            cols: vec![multiplicity_and, multiplicity_or, multiplicity_xor],
            log_size: Self::LOG_SIZE,
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
        let rel_bitwise_instr: &Self::LookupElements = lookup_elements.as_ref();
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [b_val] = preprocessed_base_column!(component_trace, PreprocessedColumn::BVal);
        let [c_val] = preprocessed_base_column!(component_trace, PreprocessedColumn::CVal);
        let [bitwise_and_a] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::BitwiseAndA);
        let [bitwise_or_a] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::BitwiseOrA);
        let [bitwise_xor_a] =
            preprocessed_base_column!(component_trace, PreprocessedColumn::BitwiseXorA);

        let [mult_and] = original_base_column!(component_trace, Column::MultiplicityAnd);
        let [mult_or] = original_base_column!(component_trace, Column::MultiplicityOr);
        let [mult_xor] = original_base_column!(component_trace, Column::MultiplicityXor);

        for (lookup_idx, a_val, mult) in [
            (AND_LOOKUP_IDX, bitwise_and_a, mult_and),
            (OR_LOOKUP_IDX, bitwise_or_a, mult_or),
            (XOR_LOOKUP_IDX, bitwise_xor_a, mult_xor),
        ] {
            let lookup_idx = BaseField::from(lookup_idx);
            logup_trace_builder.add_to_relation_with(
                rel_bitwise_instr,
                [mult],
                |[mult]| (-mult).into(),
                &[lookup_idx.into(), b_val.clone(), c_val.clone(), a_val],
            );
        }

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [b_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BVal);
        let [c_val] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::CVal);
        let [bitwise_and_a] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BitwiseAndA);
        let [bitwise_or_a] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BitwiseOrA);
        let [bitwise_xor_a] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::BitwiseXorA);

        let [mult_and] = trace_eval!(trace_eval, Column::MultiplicityAnd);
        let [mult_or] = trace_eval!(trace_eval, Column::MultiplicityOr);
        let [mult_xor] = trace_eval!(trace_eval, Column::MultiplicityXor);

        for (lookup_idx, a_val, mult) in [
            (AND_LOOKUP_IDX, bitwise_and_a, mult_and),
            (OR_LOOKUP_IDX, bitwise_or_a, mult_or),
            (XOR_LOOKUP_IDX, bitwise_xor_a, mult_xor),
        ] {
            let lookup_idx = E::F::from(BaseField::from(lookup_idx));
            let numerator: E::EF = (-mult).into();
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                numerator,
                &[lookup_idx, b_val.clone(), c_val.clone(), a_val],
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}
