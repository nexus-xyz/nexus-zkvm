use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::TraceBuilder,
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
};

use super::{trace::split_limbs, BitwiseOp, Column, PreprocessedColumn};
use crate::components::execution::{
    bitwise::columns::LowBits,
    common::ComponentTraceRef,
    decoding::type_r::{self, TypeR, TypeRDecoding},
};

pub trait TypeRBitwiseDecoding:
    TypeRDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
    const BITWISE_LOOKUP_IDX: u32;
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum TypeRColumn {
    /// Higher 4 bits of each 8-bit limb of operand op-c
    #[size = 4]
    CValHigh,
}

impl<T: TypeRBitwiseDecoding> BitwiseOp for TypeR<T> {
    const BITWISE_LOOKUP_IDX: u32 = T::BITWISE_LOOKUP_IDX;

    type LocalColumn = TypeRColumn;

    fn combine_c_val_parts<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [[E::F; WORD_SIZE]; 2] {
        let c_val_high = trace_eval!(local_trace_eval, TypeRColumn::CValHigh);
        let c_val = trace_eval!(decoding_trace_eval, type_r::DecodingColumn::CVal);

        let c_val_low = std::array::from_fn(|i| {
            c_val[i].clone() - c_val_high[i].clone() * BaseField::from(1 << 4)
        });
        [c_val_low, c_val_high]
    }

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
    ) {
        let (c_val, _) = program_step.get_value_c();
        let (_, value_c_4_7) = split_limbs(&c_val);
        trace.fill_columns(row_idx, value_c_4_7, TypeRColumn::CValHigh);
    }

    fn combine_finalized_c_val_parts(
        component_trace: &ComponentTrace,
    ) -> [[FinalizedColumn; WORD_SIZE]; 2] {
        let decoding_trace_ref =
            ComponentTraceRef::<'_, Column, type_r::DecodingColumn>::split(component_trace);
        let c_val = decoding_trace_ref.base_column(type_r::DecodingColumn::CVal);
        let c_val_low = LowBits::combine_from_column(c_val);

        // c_val_high is located at the end of the trace
        let len = component_trace.original_trace.len();
        let c_val_high =
            std::array::from_fn(|i| (&component_trace.original_trace[len - WORD_SIZE + i]).into());

        [c_val_low, c_val_high]
    }
}
