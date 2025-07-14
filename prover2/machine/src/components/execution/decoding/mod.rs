use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{builder::TraceBuilder, eval::TraceEval, program::ProgramStep};

// some instructions share local columns required for decoding across modules (e.g., type-R and type-I),
// and these are reused where possible, while others, such as loads and stores, define and use their columns locally.
//
// as a result, not all instruction types are listed here.

pub mod type_b;
pub mod type_i;
pub mod type_i_shamt;
pub mod type_r;
pub mod type_u;

mod logup_gen;
pub use logup_gen::{ComponentDecodingTrace, DecodingColumn};

pub trait InstructionDecoding {
    const OPCODE: BuiltinOpcode;
    const REG2_ACCESSED: bool;
    /// Columns used in the preprocessed (constant) trace.
    type PreprocessedColumn;
    /// Columns used in the original (main) trace.
    type MainColumn;
    /// (local) Columns used for instruction decoding. Prover commits to this trace.
    type DecodingColumn: AirColumn;

    /// Fills trace values for the decoding trace.
    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::DecodingColumn>,
        program_step: ProgramStep,
    );

    /// Constrains decoding trace values.
    fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    );

    /// Returns a linear combinations of decoding columns that represent [op-a, op-b, op-c]
    ///
    /// op-c can be an immediate or a register address.
    fn combine_reg_addresses<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; 3];

    /// Returns a linear combination of decoding columns that represent raw instruction word.
    fn combine_instr_val<E: EvalAtRow>(
        decoding_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::DecodingColumn, E>,
    ) -> [E::F; WORD_SIZE];
}

/// Register address split at the lowest bit.
pub struct RegSplitAt0<C> {
    /// Lowest bit of the register address.
    pub bit_0: C,
    /// Higher bits (bits 1 through 4) of the register address.
    pub bits_1_4: C,
}

impl<C: AirColumn> RegSplitAt0<C> {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, C, E>,
    ) -> E::F {
        let [bit_0] = trace_eval.column_eval(self.bit_0);
        let [bits_1_4] = trace_eval.column_eval(self.bits_1_4);
        bit_0 + bits_1_4 * BaseField::from(1 << 1)
    }
}

/// Register address split at the highest bit.
pub struct RegSplitAt4<C> {
    /// Lower 4 bits (bits 0 through 3) of the register address.
    pub bits_0_3: C,
    /// Highest bit (bit 4) of the register address.
    pub bit_4: C,
}

impl<C: AirColumn> RegSplitAt4<C> {
    pub fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, C, E>,
    ) -> E::F {
        let [bits_0_3] = trace_eval.column_eval(self.bits_0_3);
        let [bit_4] = trace_eval.column_eval(self.bit_4);
        bits_0_3 + bit_4 * BaseField::from(1 << 4)
    }
}
