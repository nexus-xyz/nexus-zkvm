use nexus_common::constants::{WORD_SIZE, WORD_SIZE_HALVED};
use stwo::{core::fields::m31::BaseField, prover::backend::simd::m31::PackedBaseField};

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::{
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    virtual_column::VirtualColumn,
};
use stwo_constraint_framework::EvalAtRow;

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {
    /// The current execution time
    #[size = 2]
    Clk,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Second byte in little endian representation of the program counter
    #[size = 1]
    PcNext8_15,
    /// Higher 16 bits of the program counter
    #[size = 1]
    PcHigh,
    /// Bits[2..=8] of the program counter
    #[size = 1]
    PcAux,
    /// A selector flag which is used for padding, not a computational step
    #[size = 1]
    IsPad,
}

/// Two limbs combined into a single 16 bit column.
pub struct HalfWord<C> {
    pub col: C,
    pub idx: usize,
}

impl<C: AirColumn> VirtualColumn for HalfWord<C> {
    type Column = C;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let word: [E::F; WORD_SIZE] = trace_eval.column_eval(self.col);
        word[self.idx * WORD_SIZE_HALVED].clone()
            + word[self.idx * WORD_SIZE_HALVED + 1].clone() * BaseField::from(1 << 8)
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        let word: [FinalizedColumn<'_>; WORD_SIZE] = component_trace.original_base_column(self.col);
        word[self.idx * WORD_SIZE_HALVED].at(vec_idx)
            + word[self.idx * WORD_SIZE_HALVED + 1].at(vec_idx) * BaseField::from(1 << 8)
    }
}
