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
    chips::instructions::{BitOp, BitOpLookupElements},
    components::AllLookupElements,
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

use super::{BuiltInExtension, ComponentTrace, FrameworkEvalExt};

/// A component that yields logup sum emitted by the bitwise chip.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BitOpMultiplicity {
    _private: (),
}

impl BitOpMultiplicity {
    pub(super) const fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct BitOpMultiplicityEval {
    lookup_elements: BitOpLookupElements,
}

impl BitOpMultiplicityEval {
    // There are (2 ** 4) ** 2 = 256 combinations for each looked up pair.
    pub(crate) const LOG_SIZE: u32 = 8;
}

impl FrameworkEval for BitOpMultiplicityEval {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        const PREPROCESSED_COL_IDS: &[&str] = &[
            "preprocessed_bitwise_input_b",
            "preprocessed_bitwise_input_c",
            "preprocessed_bitwise_output_and",
            "preprocessed_bitwise_output_or",
            "preprocessed_bitwise_output_xor",
        ];
        let preprocessed_columns: Vec<E::F> = PREPROCESSED_COL_IDS
            .iter()
            .map(|&id| eval.get_preprocessed_column(PreProcessedColumnId { id: id.to_owned() }))
            .collect();

        let [answer_b, answer_c, answer_a_and, answer_a_or, answer_a_xor] = preprocessed_columns
            .try_into()
            .expect("invalid number of preprocessed columns");

        let mult_and = eval.next_trace_mask();
        let mult_or = eval.next_trace_mask();
        let mult_xor = eval.next_trace_mask();

        // Subtract looked up multiplicities from logup sum
        for (op_type, answer_a, mult) in [
            (BitOp::And, answer_a_and, mult_and),
            (BitOp::Or, answer_a_or, mult_or),
            (BitOp::Xor, answer_a_xor, mult_xor),
        ] {
            let op_type = E::F::from(op_type.to_base_field());
            let numerator: E::EF = (-mult).into();
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                numerator,
                &[op_type, answer_b.clone(), answer_c.clone(), answer_a],
            ));
        }

        eval.finalize_logup();
        eval
    }
}

impl FrameworkEvalExt for BitOpMultiplicityEval {
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        let lookup_elements: &BitOpLookupElements = lookup_elements.as_ref();
        Self {
            lookup_elements: lookup_elements.clone(),
        }
    }
    fn dummy(log_size: u32) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        Self {
            lookup_elements: BitOpLookupElements::dummy(),
        }
    }
}

impl BuiltInExtension for BitOpMultiplicity {
    type Eval = BitOpMultiplicityEval;

    fn generate_component_trace(
        &self,
        log_size: u32,
        _: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace {
        let preprocessed_trace = Self::preprocessed_base_columns();
        let original_trace = Self::base_columns(side_note);

        ComponentTrace {
            log_size,
            preprocessed_trace,
            original_trace,
        }
    }

    fn compute_log_size(&self, _side_note: &SideNote) -> u32 {
        BitOpMultiplicityEval::LOG_SIZE
    }

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program_trace_ref: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::preprocessed_base_columns();
        let domain = CanonicCoset::new(BitOpMultiplicityEval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn preprocessed_trace_sizes(_log_size: u32) -> Vec<u32> {
        // preprocessed column for each of [and, or, xor] with 2 input lookups
        vec![BitOpMultiplicityEval::LOG_SIZE; 5]
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
        let lookup_element: &BitOpLookupElements = lookup_elements.as_ref();
        let mut logup_trace_gen = LogupTraceGenerator::new(BitOpMultiplicityEval::LOG_SIZE);

        // Subtract looked up multiplicities from logup sum
        let preprocessed_columns = &component_trace.preprocessed_trace;
        let base_columns = &component_trace.original_trace;

        let [answer_b, answer_c, answer_a_and, answer_a_or, answer_a_xor] =
            std::array::from_fn(|i| &preprocessed_columns[i]);
        let [mult_and, mult_or, mult_xor] = std::array::from_fn(|i| &base_columns[i]);

        for (op_type, answer_a, mult) in [
            (BitOp::And, &answer_a_and, &mult_and),
            (BitOp::Or, &answer_a_or, &mult_or),
            (BitOp::Xor, &answer_a_xor, &mult_xor),
        ] {
            let mut logup_col_gen = logup_trace_gen.new_col();
            for vec_row in 0..(1 << (BitOpMultiplicityEval::LOG_SIZE - LOG_N_LANES)) {
                let answer_tuple = vec![
                    op_type.to_packed_base_field(),
                    answer_b.data[vec_row],
                    answer_c.data[vec_row],
                    answer_a.data[vec_row],
                ];
                let denom = lookup_element.combine(&answer_tuple);
                let numerator = mult.data[vec_row];
                logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
            }
            logup_col_gen.finalize_col();
        }

        logup_trace_gen.finalize_last()
    }
}

impl BitOpMultiplicity {
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let range_iter = (0u8..16).flat_map(|b| (0u8..16).map(move |c| (b, c)));
        let column_b = BaseColumn::from_iter(range_iter.clone().map(|(b, _)| u32::from(b).into()));
        let column_c = BaseColumn::from_iter(range_iter.clone().map(|(_, c)| u32::from(c).into()));
        let column_and =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b & c).into()));
        let column_or =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b | c).into()));
        let column_xor =
            BaseColumn::from_iter(range_iter.clone().map(|(b, c)| u32::from(b ^ c).into()));

        vec![column_b, column_c, column_and, column_or, column_xor]
    }

    fn base_columns(side_note: &SideNote) -> Vec<BaseColumn> {
        let multiplicity_and = &side_note.bit_op.multiplicity_and;
        let multiplicity_or = &side_note.bit_op.multiplicity_or;
        let multiplicity_xor = &side_note.bit_op.multiplicity_xor;

        let multiplicity_and = BaseColumn::from_iter(
            (0..=255).map(|i| multiplicity_and.get(&i).copied().unwrap_or_default().into()),
        );
        let multiplicity_or = BaseColumn::from_iter(
            (0..=255).map(|i| multiplicity_or.get(&i).copied().unwrap_or_default().into()),
        );
        let multiplicity_xor = BaseColumn::from_iter(
            (0..=255).map(|i| multiplicity_xor.get(&i).copied().unwrap_or_default().into()),
        );
        vec![multiplicity_and, multiplicity_or, multiplicity_xor]
    }
}
