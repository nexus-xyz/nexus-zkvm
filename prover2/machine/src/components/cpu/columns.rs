use nexus_common::constants::{WORD_SIZE, WORD_SIZE_HALVED};
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::{
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    virtual_column::{ColumnSum, VirtualColumn},
};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {
    /// The current execution time
    #[size = 2]
    Clk,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current value of the program counter register
    #[size = 4]
    Pc,
    /// Auxiliary variable used for program counter arithmetic
    #[size = 1]
    PcAux,
    /// The opcode defining the instruction
    #[size = 1]
    Opcode,
    /// The value of operand op-a
    #[size = 4]
    AVal,
    /// The value of operand op-b
    #[size = 4]
    BVal,
    /// The value of operand op-c
    #[size = 4]
    CVal,
    /// The address of the first operand of the instruction
    #[size = 1]
    OpA,
    /// The address of the second operand of the instruction
    #[size = 1]
    OpB,
    /// The address of the third operand of the instruction
    #[size = 1]
    OpC,

    // Instruction flags
    /// Selector flag which indicates an ADD operation
    #[size = 1]
    IsAdd,
    /// Selector flag which indicates an ADD operation
    #[size = 1]
    IsAddI,
    /// A selector flag which is used for padding, not a computational step
    #[size = 1]
    IsPad,
}

/// Lower 16 bits of pc
pub const PC_LOW: HalfWord<Column> = HalfWord {
    col: Column::Pc,
    idx: 0,
};

/// Higher 16 bits of pc
pub const PC_HIGH: HalfWord<Column> = HalfWord {
    col: Column::Pc,
    idx: 1,
};

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

/// is-type-r = is-add + is-sub + is-slt + is-sltu + is-xor + is-or + is-and + is-sll + is-srl + is-sra
pub const IS_TYPE_R: ColumnSum<Column> = ColumnSum::new(&[Column::IsAdd]);

/// is-alu-imm-no-shift = is-addi + is-slti + is-sltiu + is-xori + is-ori + is-andi
pub const IS_ALU_IMM_NO_SHIFT: ColumnSum<Column> = ColumnSum::new(&[Column::IsAddI]);

/// is-alu = is-type-r + is-alu-imm-no-shift + is-alu-imm-shift
pub const IS_ALU: IsAlu = IsAlu;

pub struct IsAlu;

impl VirtualColumn for IsAlu {
    type Column = Column;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let is_type_r = IS_TYPE_R.eval(trace_eval);
        let is_alu_imm_no_shift = IS_ALU_IMM_NO_SHIFT.eval(trace_eval);

        is_type_r + is_alu_imm_no_shift
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        let is_type_r = IS_TYPE_R.combine_at_row(component_trace, vec_idx);
        let is_alu_imm_no_shift = IS_ALU_IMM_NO_SHIFT.combine_at_row(component_trace, vec_idx);

        is_type_r + is_alu_imm_no_shift
    }
}
