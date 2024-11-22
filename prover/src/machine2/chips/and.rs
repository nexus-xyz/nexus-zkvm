use num_traits::{One as _, Zero as _};
use stwo_prover::{
    constraint_framework::{
        logup::{LogupAtRow, LogupTraceGenerator, LookupElements},
        EvalAtRow, INTERACTION_TRACE_IDX,
    },
    core::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        fields::{
            m31::{self, BaseField},
            qm31::SecureField,
        },
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::machine2::{
    column::{
        Column::{self, IsAnd, MultiplicityAnd, ValueA, ValueAEffective, ValueB, ValueC},
        PreprocessedColumn::{self, BitwiseAndByteA, BitwiseByteB, BitwiseByteC, IsFirst},
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        ProgramStep, Traces, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

// Support AND and ANDI opcodes.
pub struct AndChip;

pub struct ExecutionResult {
    and_bytes: Word,
    /// true when destination register is writable (not X0)
    value_a_effective_flag: bool,
}

impl ExecuteChip for AndChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let value_a_effective_flag = program_step.value_a_effectitve_flag();

        // Step 1. Break the computation to 8-bit limbs
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut value_a = Word::default();

        // Step 2. Compute the output.
        for i in 0..WORD_SIZE {
            value_a[i] = value_b[i] & value_c[i];
        }

        ExecutionResult {
            and_bytes: value_a,
            value_a_effective_flag,
        }
    }
}

impl MachineChip for AndChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if vm_step.step.is_padding {
            return;
        }
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::AND) | Some(BuiltinOpcode::ANDI)
        ) {
            return;
        }

        let ExecutionResult {
            and_bytes,
            value_a_effective_flag,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        debug_assert_eq!(
            and_bytes,
            vm_step
                .get_result()
                .expect("AND/ANDI instruction must have a result")
        );

        // Increment MultiplicityAnd[b[i] * 256 + c[i]]
        let b_word = vm_step.get_value_b();
        let (c_word, _) = vm_step.get_value_c();
        let mut counter: u32 = 0; // for detecting global multiplicity overflow
        for limb_idx in 0..WORD_SIZE {
            debug_assert_eq!(b_word[limb_idx] & c_word[limb_idx], and_bytes[limb_idx]);
            // The tuple (b, c, b ^ c) is located at row_idx b * 256 + c. This is due to nested 0..256 loops.
            let looked_up_row = (b_word[limb_idx] as usize) * 256 + c_word[limb_idx] as usize;
            let multiplicity_col: [&mut BaseField; 1] =
                traces.column_mut(looked_up_row, MultiplicityAnd);
            *multiplicity_col[0] += BaseField::one();
            // Detect overflow: there's a soundness problem if the multiplicity overflows
            assert_ne!(*multiplicity_col[0], BaseField::zero());
            // Detect global overflow: there is a soundness problem if this chip is used to check 2^31-1 pairs or more.
            counter += 1;
            assert_ne!(counter, m31::P);
        }

        traces.fill_columns(row_idx, &and_bytes, ValueA);
        traces.fill_effective_columns(row_idx, &and_bytes, ValueAEffective, value_a_effective_flag);
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen rows.
    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_trace: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked pairs to logup sum
        let [is_and] = original_traces.get_base_column(IsAnd);
        let value_a: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueA);
        let value_b: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueB);
        let value_c: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueC);
        for limb_idx in 0..WORD_SIZE {
            let mut logup_col_gen = logup_trace_gen.new_col();
            // vec_row is row_idx divided by 16. Because SIMD.
            for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
                let checked_a = value_a[limb_idx].data[vec_row];
                let checked_b = value_b[limb_idx].data[vec_row];
                let checked_c = value_c[limb_idx].data[vec_row];
                let checked_tuple = vec![checked_b, checked_c, checked_a];
                let denom = lookup_element.combine(&checked_tuple);
                let numerator = is_and.data[vec_row];
                logup_col_gen.write_frac(vec_row, numerator.into(), denom);
            }
            logup_col_gen.finalize_col();
        }

        // Subtract looked up multiplicities from logup sum
        let [answer_b] = preprocessed_trace.get_preprocessed_base_column(BitwiseByteB);
        let [answer_c] = preprocessed_trace.get_preprocessed_base_column(BitwiseByteC);
        let [answer_a] = preprocessed_trace.get_preprocessed_base_column(BitwiseAndByteA);
        let [mult] = original_traces.get_base_column(MultiplicityAnd);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let answer_tuple = vec![
                answer_b.data[vec_row],
                answer_c.data[vec_row],
                answer_a.data[vec_row],
            ];
            let denom = lookup_element.combine(&answer_tuple);
            let numerator = mult.data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
        let (ret, total_logup_sum) = logup_trace_gen.finalize_last();
        debug_assert_eq!(total_logup_sum, SecureField::zero());
        ret
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let (_, [is_first]) = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum
        let (_, [is_and]) = trace_eval!(trace_eval, IsAnd);
        let (_, value_a) = trace_eval!(trace_eval, ValueA);
        let (_, value_b) = trace_eval!(trace_eval, ValueB);
        let (_, value_c) = trace_eval!(trace_eval, ValueC);
        for limb_idx in 0..WORD_SIZE {
            let denom: E::EF = lookup_elements.combine(&[
                value_b[limb_idx].clone(),
                value_c[limb_idx].clone(),
                value_a[limb_idx].clone(),
            ]);
            let numerator: E::EF = is_and.clone().into();
            logup.write_frac(eval, Fraction::new(numerator, denom));
        }
        // Subtract looked up multiplicities from logup sum
        let (_, [answer_b]) = preprocessed_trace_eval!(trace_eval, BitwiseByteB);
        let (_, [answer_c]) = preprocessed_trace_eval!(trace_eval, BitwiseByteC);
        let (_, [answer_a]) = preprocessed_trace_eval!(trace_eval, BitwiseAndByteA);
        let (_, [mult]) = trace_eval!(trace_eval, MultiplicityAnd);
        let denom: E::EF =
            lookup_elements.combine(&[answer_b.clone(), answer_c.clone(), answer_a.clone()]);
        let numerator: E::EF = (-mult.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

#[cfg(test)]
mod test {
    use crate::{
        machine2::chips::{AddChip, CpuChip},
        utils::assert_chip,
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = Traces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        #[rustfmt::skip]
        let basic_block = BasicBlock::new(vec![
            // 0b11100 & 0b01010 = 0b01000
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 28, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 8, InstructionType::IType),
            // x3 = x1 & x2
            Instruction::new(Opcode::from(BuiltinOpcode::AND), 3, 1, 2, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_values() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let mut traces = Traces::new(LOG_SIZE);

        for (row_idx, trace) in vm_traces.blocks.iter().enumerate() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // Fill in the main trace with the ValueB, valueC and Opcode
                CpuChip::fill_main_trace(&mut traces, row_idx, &program_step);
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step);
                AndChip::fill_main_trace(&mut traces, row_idx, &program_step);
            }
        }

        let vals = traces
            .column(2, ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(vals);

        assert_eq!(output, 0b1000);

        assert_chip::<AndChip>(traces);
    }
}
