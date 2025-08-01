use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{
    builder::TraceBuilder,
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::ProgramStep,
    virtual_column::VirtualColumn,
};

use super::{BitwiseOp, Column, PreprocessedColumn};
use crate::components::execution::{
    common::ComponentTraceRef,
    decoding::type_i::{self, TypeI, TypeIDecoding},
};

pub trait TypeIBitwiseDecoding:
    TypeIDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
    const BITWISE_LOOKUP_IDX: u32;
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum EmptyColumn {}

impl<T: TypeIBitwiseDecoding> BitwiseOp for TypeI<T> {
    const BITWISE_LOOKUP_IDX: u32 = T::BITWISE_LOOKUP_IDX;

    type LocalColumn = EmptyColumn;

    fn combine_c_val_parts<E: EvalAtRow>(
        _local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let [op_c0_3] = decoding_trace_eval.column_eval(type_i::DecodingColumn::OpC0_3);
        let [op_c4_7] = decoding_trace_eval.column_eval(type_i::DecodingColumn::OpC4_7);

        let c_val_low_1 = CValLow1.eval(decoding_trace_eval);
        let op_c11_ext = OpC11Ext.eval(decoding_trace_eval);

        let c_val_low = [op_c0_3, c_val_low_1, op_c11_ext.clone(), op_c11_ext.clone()];

        let c_val_high = [
            op_c4_7,
            op_c11_ext.clone(),
            op_c11_ext.clone(),
            op_c11_ext.clone(),
        ];

        [c_val_low, c_val_high]
    }

    fn generate_trace_row(
        _row_idx: usize,
        _trace: &mut TraceBuilder<Self::LocalColumn>,
        _program_step: ProgramStep,
    ) {
    }

    fn combine_finalized_c_val_parts(
        component_trace: &ComponentTrace,
    ) -> [[FinalizedColumn; WORD_SIZE]; 2] {
        let op_c0_3 = &component_trace.original_trace
            [Column::COLUMNS_NUM + type_i::DecodingColumn::OpC0_3.offset()];
        let op_c4_7 = &component_trace.original_trace
            [Column::COLUMNS_NUM + type_i::DecodingColumn::OpC4_7.offset()];

        let c_val_low_1 = CValLow1.combine_from_finalized_trace(component_trace);
        let op_c11_ext = OpC11Ext.combine_from_finalized_trace(component_trace);

        let c_val_low = [
            op_c0_3.into(),
            c_val_low_1,
            op_c11_ext.clone(),
            op_c11_ext.clone(),
        ];
        let c_val_high = [
            op_c4_7.into(),
            op_c11_ext.clone(),
            op_c11_ext.clone(),
            op_c11_ext.clone(),
        ];
        [c_val_low, c_val_high]
    }
}

/// Second byte of c-val-low
struct CValLow1;

impl VirtualColumn for CValLow1 {
    type Column = type_i::DecodingColumn;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let [op_c8_10] = trace_eval.column_eval(type_i::DecodingColumn::OpC8_10);
        let [op_c11] = trace_eval.column_eval(type_i::DecodingColumn::OpC11);
        op_c8_10 + op_c11 * BaseField::from(1 << 3)
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        let decoding_trace_ref =
            ComponentTraceRef::<'_, Column, type_i::DecodingColumn>::split(component_trace);
        let op_c8_10 =
            decoding_trace_ref.base_column::<1>(type_i::DecodingColumn::OpC8_10)[0].at(vec_idx);
        let op_c11 =
            decoding_trace_ref.base_column::<1>(type_i::DecodingColumn::OpC11)[0].at(vec_idx);

        op_c8_10 + op_c11 * BaseField::from(1 << 3)
    }
}

/// op_c11 bit extended to half byte
struct OpC11Ext;

impl VirtualColumn for OpC11Ext {
    type Column = type_i::DecodingColumn;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let [op_c11] = trace_eval.column_eval(type_i::DecodingColumn::OpC11);
        op_c11 * BaseField::from((1 << 4) - 1)
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        let decoding_trace_ref =
            ComponentTraceRef::<'_, Column, type_i::DecodingColumn>::split(component_trace);
        let op_c11 =
            decoding_trace_ref.base_column::<1>(type_i::DecodingColumn::OpC11)[0].at(vec_idx);

        op_c11 * BaseField::from((1 << 4) - 1)
    }
}
