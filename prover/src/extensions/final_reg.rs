use nexus_common::constants::NUM_REGISTERS;
use nexus_vm::WORD_SIZE;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{
        logup::LogupTraceGenerator, preprocessed_columns::PreProcessedColumnId, FrameworkEval,
        Relation, RelationEntry,
    },
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, PackedM31, LOG_N_LANES},
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
    chips::memory_check::register_mem_check::RegisterCheckLookupElements,
    components::AllLookupElements,
    trace::{sidenote::SideNote, utils::IntoBaseFields},
};

use super::{BuiltInExtension, FrameworkEvalExt};

/// A column with {0, ..., 31}
#[derive(Debug, Clone)]
pub struct RegisterIdx;

impl RegisterIdx {
    pub const fn new(_log_size: u32) -> Self {
        Self {}
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!("preprocessed_register_idx_{}", FinalRegEval::LOG_SIZE),
        }
    }
}

/// A component for the final register memory state
#[derive(Debug, Clone)]
pub struct FinalReg {
    _private: (),
}

impl FinalReg {
    pub(super) const fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct FinalRegEval {
    lookup_elements: RegisterCheckLookupElements,
}

impl Default for FinalRegEval {
    fn default() -> Self {
        Self {
            lookup_elements: RegisterCheckLookupElements::dummy(),
        }
    }
}

impl FinalRegEval {
    // There are 32 registers, so 2^5 = 32 rows are needed.
    const LOG_SIZE: u32 = 5;
    const TUPLE_SIZE: usize = 1 + 2 * WORD_SIZE;
}

impl FrameworkEval for FinalRegEval {
    fn log_size(&self) -> u32 {
        Self::LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        Self::LOG_SIZE + 1
    }

    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        // Need to read all columns so that the information evaluator returns the correct dimension.
        // let _reg_idx = eval.next_trace_mask();
        let reg_idx = RegisterIdx::new(FinalRegEval::LOG_SIZE);
        let reg_idx = eval.get_preprocessed_column(reg_idx.id());
        let final_timestamp: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let final_value: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();

        // Add initial register memory state
        let mut tuple: [E::F; Self::TUPLE_SIZE] = std::array::from_fn(|_| E::F::zero());
        tuple[0] = reg_idx.clone();
        let numerator = E::F::one();

        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            numerator.into(),
            tuple.as_slice(),
        ));

        // Remove final register memory state
        let mut tuple = vec![reg_idx];
        for elm in final_timestamp.into_iter().chain(final_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);
        let numerator = -E::F::one();
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            numerator.into(),
            &tuple,
        ));

        eval.finalize_logup();

        eval
    }
}

impl FrameworkEvalExt for FinalRegEval {
    fn log_size() -> u32 {
        Self::LOG_SIZE
    }

    fn new(lookup_elements: &AllLookupElements) -> Self {
        let register_check_lookup_elements: &RegisterCheckLookupElements = lookup_elements.as_ref();
        Self {
            lookup_elements: register_check_lookup_elements.clone(),
        }
    }
}

impl BuiltInExtension for FinalReg {
    type Eval = FinalRegEval;

    fn generate_preprocessed_trace(
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::preprocessed_base_columns();
        let domain = CanonicCoset::new(FinalRegEval::LOG_SIZE).circle_domain();
        base_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn preprocessed_trace_sizes() -> Vec<u32> {
        vec![FinalRegEval::LOG_SIZE]
    }

    /// The first four columns represent the final values, the following four columns represent the final timestamps.
    ///
    /// The ordering of rows corresponds to the register index in the preprocessed trace.
    fn generate_original_trace(
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let base_cols = Self::base_columns(side_note);
        let domain = CanonicCoset::new(FinalRegEval::LOG_SIZE).circle_domain();
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
        let lookup_element: &RegisterCheckLookupElements = lookup_elements.as_ref();

        let mut logup_trace_gen = LogupTraceGenerator::new(FinalRegEval::LOG_SIZE);
        let row_idx = &Self::preprocessed_base_columns()[0];
        let base_cols = Self::base_columns(side_note);

        // Adding the initial register memory state
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (FinalRegEval::LOG_SIZE - LOG_N_LANES)) {
            let row_idx = row_idx.data[vec_row];
            let mut tuple: [PackedM31; FinalRegEval::TUPLE_SIZE] =
                [BaseField::zero().into(); FinalRegEval::TUPLE_SIZE]; // reg_idx, cur_timestamp, cur_value
            tuple[0] = row_idx; // Use row_idx as register index
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = PackedBaseField::broadcast(BaseField::one());
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();

        // Subtracting the final register memory state
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (FinalRegEval::LOG_SIZE - LOG_N_LANES)) {
            let row_idx = row_idx.data[vec_row];
            let mut tuple = vec![row_idx];
            for col in base_cols.iter() {
                tuple.push(col.data[vec_row]);
            }
            assert_eq!(tuple.len(), FinalRegEval::TUPLE_SIZE);
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = PackedBaseField::broadcast(-BaseField::one());
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();

        logup_trace_gen.finalize_last()
    }
}

impl FinalReg {
    fn preprocessed_base_columns() -> Vec<BaseColumn> {
        let reg_idx = BaseColumn::from_iter((0..32).map(BaseField::from));
        vec![reg_idx]
    }
    fn base_columns(side_note: &SideNote) -> Vec<BaseColumn> {
        let mut base_cols: Vec<BaseColumn> = vec![];
        let final_timestamps = (0..NUM_REGISTERS).map(|reg_idx| {
            side_note.register_mem_check.last_access_timestamp[reg_idx as usize].into_base_fields()
        });
        for i in 0..WORD_SIZE {
            let col = final_timestamps.clone().map(|val| val[i]);
            base_cols.push(BaseColumn::from_iter(col));
        }
        let final_values = (0..NUM_REGISTERS).map(|reg_idx| {
            side_note.register_mem_check.last_access_value[reg_idx as usize].into_base_fields()
        });
        for i in 0..WORD_SIZE {
            let col = final_values.clone().map(|val| val[i]);
            base_cols.push(BaseColumn::from_iter(col));
        }
        assert_eq!(base_cols.len(), 2 * WORD_SIZE);
        base_cols
    }
}
