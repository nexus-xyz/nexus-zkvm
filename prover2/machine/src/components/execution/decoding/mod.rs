use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::column::BaseColumn, fields::m31::BaseField},
};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::{component::ComponentTrace, eval::TraceEval, program::ProgramStep};

// some instructions share local columns required for decoding across modules (e.g., type-R and type-I),
// and these are reused where possible, while others, such as loads and stores, define and use their columns locally.
//
// as a result, not all instruction types are listed here.

pub mod type_i;
pub mod type_r;

/// Column for indexing decoding trace, these values are used by the prover
/// for the program memory checking logup trace generation.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum VirtualDecodingColumn {
    /// The address of the first operand of the instruction
    #[size = 1]
    OpA,
    /// The address of the second operand of the instruction
    #[size = 1]
    OpB,
    /// The address of the third operand of the instruction
    #[size = 1]
    OpC,
    /// The 32-bit instruction word stored at address pc
    #[size = 4]
    InstrVal,
}

/// Returns decoding trace from the program steps iterator.
///
/// Prover doesn't commit to this trace.
pub fn instruction_decoding_trace<'a, I: Iterator<Item = ProgramStep<'a>>>(
    log_size: u32,
    iter: I,
) -> ComponentTrace {
    let program_steps: Vec<ProgramStep<'a>> = iter.collect();
    let pad_len = (1usize << log_size)
        .checked_sub(program_steps.len())
        .expect("padding underflow caused by incorrect log size");

    let mut result = Vec::with_capacity(VirtualDecodingColumn::COLUMNS_NUM);

    let op_a_iter = program_steps
        .iter()
        .map(|step| step.get_op_a() as u8 as u32)
        .chain(std::iter::repeat_n(0, pad_len));
    let op_b_iter = program_steps
        .iter()
        .map(|step| step.get_op_b() as u8 as u32)
        .chain(std::iter::repeat_n(0, pad_len));
    let op_c_iter = program_steps
        .iter()
        .map(ProgramStep::get_op_c)
        .chain(std::iter::repeat_n(0, pad_len));

    result.push(BaseColumn::from_iter(op_a_iter.map(BaseField::from)));
    result.push(BaseColumn::from_iter(op_b_iter.map(BaseField::from)));
    result.push(BaseColumn::from_iter(op_c_iter.map(BaseField::from)));
    for i in 0..WORD_SIZE {
        let col_iter = program_steps
            .iter()
            .map(|step| (step.step.raw_instruction >> (i * 8)) & 255)
            .chain(std::iter::repeat_n(0, pad_len));
        result.push(BaseColumn::from_iter(col_iter.map(BaseField::from)));
    }
    ComponentTrace {
        log_size,
        preprocessed_trace: Vec::new(),
        original_trace: result,
    }
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
