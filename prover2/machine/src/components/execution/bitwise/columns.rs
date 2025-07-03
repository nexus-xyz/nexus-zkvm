#![allow(clippy::op_ref)]

use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
        },
        fields::m31::BaseField,
    },
};

use nexus_common::constants::WORD_SIZE;
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The next execution time represented by four 16-bit limbs
    #[size = 2]
    ClkNext,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// A 32-bit word specifying the value of operand op-a represented by four 8-bit limbs
    #[size = 4]
    AVal,
    /// A 32-bit word specifying the value of operand op-b represented by four 8-bit limbs
    #[size = 4]
    BVal,
    /// A 32-bit word specifying the value of operand op-c represented by four 8-bit limbs
    #[size = 4]
    CVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The helper bits to compute the program counter update
    #[size = 1]
    PcCarry,
    /// The next value of the program counter register after the execution
    #[size = 2]
    PcNext,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Higher 4 bits of each 8-bit limb of operand op-a
    #[size = 4]
    AValHigh,
    /// Higher 4 bits of each 8-bit limb of operand op-b
    #[size = 4]
    BValHigh,
    /// Higher 4 bits of each 8-bit limb of operand op-c
    #[size = 4]
    CValHigh,
}

pub struct LowBits {
    col: Column,
    col_high: Column,
}

impl LowBits {
    pub fn eval<E: EvalAtRow>(
        &self,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
    ) -> [E::F; WORD_SIZE] {
        let word: [E::F; WORD_SIZE] = trace_eval.column_eval(self.col);
        let high_bits: [E::F; WORD_SIZE] = trace_eval.column_eval(self.col_high);

        std::array::from_fn(|i| word[i].clone() - high_bits[i].clone() * BaseField::from(1 << 4))
    }

    pub fn combine_from_finalized_trace(
        &self,
        component_trace: &ComponentTrace,
    ) -> [FinalizedColumn; WORD_SIZE] {
        let word: [_; WORD_SIZE] = component_trace.original_base_column(self.col);

        let low_bits = word.map(|col| {
            let FinalizedColumn::Column(col) = col else {
                panic!("original trace column type mismatch")
            };
            let low_bits = col
                .data
                .iter()
                .map(|word| {
                    // SAFETY:
                    //
                    // Taking the lower 4 bits of a range-checked M31 field element is a non-increasing
                    // operation and cannot overflow.
                    unsafe {
                        PackedBaseField::from_simd_unchecked(
                            word.into_simd() & &[0xF; 1 << LOG_N_LANES].into(),
                        )
                    }
                })
                .collect();
            FinalizedColumn::new_virtual(BaseColumn::from_simd(low_bits))
        });

        low_bits
    }
}

pub const A_VAL_LOW: LowBits = LowBits {
    col: Column::AVal,
    col_high: Column::AValHigh,
};

pub const B_VAL_LOW: LowBits = LowBits {
    col: Column::BVal,
    col_high: Column::BValHigh,
};

pub const C_VAL_LOW: LowBits = LowBits {
    col: Column::CVal,
    col_high: Column::CValHigh,
};
