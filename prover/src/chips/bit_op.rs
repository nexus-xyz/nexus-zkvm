use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{
        logup::{LogupAtRow, LogupTraceGenerator, LookupElements},
        EvalAtRow, INTERACTION_TRACE_IDX,
    },
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
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

use crate::{
    column::{
        Column::{
            self, IsAnd, IsOr, IsXor, MultiplicityAnd, MultiplicityOr, MultiplicityXor, ValueA,
            ValueB, ValueC,
        },
        PreprocessedColumn::{
            self, BitwiseAndByteA, BitwiseByteB, BitwiseByteC, BitwiseOrByteA, BitwiseXorByteA,
            IsFirst,
        },
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        PreprocessedTraces, ProgramStep, Traces, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

// Support bitwise operations opcode with lookups.
pub struct BitOpChip;

/// Unit-enum indicating which bitwise operation is executed by the chip.
///
/// Note that its numeric value is used as the first element in the tuple to enforce the
/// difference between lookups. Otherwise, the verifier can't differentiate between
/// (is_and, is_or) == (one(), zero()) and (is_and, is_or) == (zero(), one()) for the
/// same denominator in the logup fraction.
#[derive(Debug, Copy, Clone)]
enum BitOp {
    And = 1,
    Or = 2,
    Xor = 3,
}

impl BitOp {
    /// Converts an operation flag into a field element.
    fn to_base_field(self) -> BaseField {
        BaseField::from(self as u32)
    }

    /// Converts an operation flag into a SIMD vector of repeating elements.
    fn to_packed_base_field(self) -> PackedBaseField {
        PackedBaseField::broadcast((self as u32).into())
    }
}

pub struct ExecutionResult {
    out_bytes: Word,
    bit_op: BitOp,
}

impl ExecuteChip for BitOpChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let bit_op = match program_step
            .step
            .instruction
            .opcode
            .builtin()
            .expect("built-in opcode expected")
        {
            BuiltinOpcode::AND | BuiltinOpcode::ANDI => BitOp::And,
            BuiltinOpcode::OR | BuiltinOpcode::ORI => BitOp::Or,
            BuiltinOpcode::XOR | BuiltinOpcode::XORI => BitOp::Xor,
            _ => panic!("unsupported opcode for bit chip"),
        };
        // Step 1. Break the computation to 8-bit limbs
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut value_a = Word::default();

        // Step 2. Compute the output.
        for i in 0..WORD_SIZE {
            let b = value_b[i];
            let c = value_c[i];
            value_a[i] = match bit_op {
                BitOp::And => b & c,
                BitOp::Or => b | c,
                BitOp::Xor => b ^ c,
            };
        }

        ExecutionResult {
            out_bytes: value_a,
            bit_op,
        }
    }
}

impl MachineChip for BitOpChip {
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::AND)
                | Some(BuiltinOpcode::ANDI)
                | Some(BuiltinOpcode::OR)
                | Some(BuiltinOpcode::ORI)
                | Some(BuiltinOpcode::XOR)
                | Some(BuiltinOpcode::XORI)
        ) {
            return;
        }

        let ExecutionResult { out_bytes, bit_op } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        debug_assert_eq!(
            out_bytes,
            vm_step
                .get_result()
                .expect("Bitwise instruction must have a result")
        );

        // Increment Multiplicity(And/Or)[b[i] * 256 + c[i]]
        let b_word = vm_step.get_value_b();
        let (c_word, _) = vm_step.get_value_c();
        let mut counter: u32 = 0; // for detecting global multiplicity overflow
        for limb_idx in 0..WORD_SIZE {
            // The tuple (b, c, b ^ c) is located at row_idx b * 256 + c. This is due to nested 0..256 loops.
            let looked_up_row = (b_word[limb_idx] as usize) * 256 + c_word[limb_idx] as usize;
            let multiplicity = match bit_op {
                BitOp::And => MultiplicityAnd,
                BitOp::Or => MultiplicityOr,
                BitOp::Xor => MultiplicityXor,
            };
            let multiplicity_col: [&mut BaseField; 1] =
                traces.column_mut(looked_up_row, multiplicity);
            *multiplicity_col[0] += BaseField::one();
            // Detect overflow: there's a soundness problem if the multiplicity overflows
            assert_ne!(*multiplicity_col[0], BaseField::zero());
            // Detect global overflow: there is a soundness problem if this chip is used to check 2^31-1 pairs or more.
            counter += 1;
            assert_ne!(counter, m31::P);
        }

        traces.fill_columns(row_idx, out_bytes, ValueA);
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen rows.
    fn fill_interaction_trace(
        original_traces: &Traces,
        preprocessed_trace: &PreprocessedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked pairs to logup sum
        let [is_and] = original_traces.get_base_column(IsAnd);
        let [is_or] = original_traces.get_base_column(IsOr);
        let [is_xor] = original_traces.get_base_column(IsXor);
        let value_a: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueA);
        let value_b: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueB);
        let value_c: [BaseColumn; WORD_SIZE] = original_traces.get_base_column(ValueC);
        for limb_idx in 0..WORD_SIZE {
            for (op_type, is_op) in [
                (BitOp::And, &is_and),
                (BitOp::Or, &is_or),
                (BitOp::Xor, &is_xor),
            ] {
                let mut logup_col_gen = logup_trace_gen.new_col();
                // vec_row is row_idx divided by 16. Because SIMD.
                for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
                    let op_type = op_type.to_packed_base_field();
                    let checked_a = value_a[limb_idx].data[vec_row];
                    let checked_b = value_b[limb_idx].data[vec_row];
                    let checked_c = value_c[limb_idx].data[vec_row];
                    let checked_tuple = vec![op_type, checked_b, checked_c, checked_a];
                    let denom = lookup_element.combine(&checked_tuple);
                    let numerator = is_op.data[vec_row];
                    logup_col_gen.write_frac(vec_row, numerator.into(), denom);
                }
                logup_col_gen.finalize_col();
            }
        }

        // Subtract looked up multiplicities from logup sum
        let [answer_b] = preprocessed_trace.get_preprocessed_base_column(BitwiseByteB);
        let [answer_c] = preprocessed_trace.get_preprocessed_base_column(BitwiseByteC);

        let [answer_a_and] = preprocessed_trace.get_preprocessed_base_column(BitwiseAndByteA);
        let [mult_and] = original_traces.get_base_column(MultiplicityAnd);

        let [answer_a_or] = preprocessed_trace.get_preprocessed_base_column(BitwiseOrByteA);
        let [mult_or] = original_traces.get_base_column(MultiplicityOr);

        let [answer_a_xor] = preprocessed_trace.get_preprocessed_base_column(BitwiseXorByteA);
        let [mult_xor] = original_traces.get_base_column(MultiplicityXor);
        for (op_type, answer_a, mult) in [
            (BitOp::And, &answer_a_and, &mult_and),
            (BitOp::Or, &answer_a_or, &mult_or),
            (BitOp::Xor, &answer_a_xor, &mult_xor),
        ] {
            let mut logup_col_gen = logup_trace_gen.new_col();
            for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
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
        let (ret, total_logup_sum) = logup_trace_gen.finalize_last();
        debug_assert_eq!(total_logup_sum, SecureField::zero());
        ret
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let ([is_first], _) = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum
        let [is_and] = trace_eval!(trace_eval, IsAnd);
        let [is_or] = trace_eval!(trace_eval, IsOr);
        let [is_xor] = trace_eval!(trace_eval, IsXor);
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        for limb_idx in 0..WORD_SIZE {
            for (op_type, is_op) in [
                (BitOp::And, &is_and),
                (BitOp::Or, &is_or),
                (BitOp::Xor, &is_xor),
            ] {
                let op_type = E::F::from(op_type.to_base_field());
                let denom: E::EF = lookup_elements.combine(&[
                    op_type,
                    value_b[limb_idx].clone(),
                    value_c[limb_idx].clone(),
                    value_a[limb_idx].clone(),
                ]);
                let numerator: E::EF = is_op.clone().into();
                logup.write_frac(eval, Fraction::new(numerator, denom.clone()));
            }
        }

        // Subtract looked up multiplicities from logup sum
        let ([answer_b], _) = preprocessed_trace_eval!(trace_eval, BitwiseByteB);
        let ([answer_c], _) = preprocessed_trace_eval!(trace_eval, BitwiseByteC);

        let ([answer_a_and], _) = preprocessed_trace_eval!(trace_eval, BitwiseAndByteA);
        let [mult_and] = trace_eval!(trace_eval, MultiplicityAnd);

        let ([answer_a_or], _) = preprocessed_trace_eval!(trace_eval, BitwiseOrByteA);
        let [mult_or] = trace_eval!(trace_eval, MultiplicityOr);

        let ([answer_a_xor], _) = preprocessed_trace_eval!(trace_eval, BitwiseXorByteA);
        let [mult_xor] = trace_eval!(trace_eval, MultiplicityXor);
        for (op_type, answer_a, mult) in [
            (BitOp::And, answer_a_and, mult_and),
            (BitOp::Or, answer_a_or, mult_or),
            (BitOp::Xor, answer_a_xor, mult_xor),
        ] {
            let op_type = E::F::from(op_type.to_base_field());
            let denom: E::EF =
                lookup_elements.combine(&[op_type, answer_b.clone(), answer_c.clone(), answer_a]);
            let numerator: E::EF = (-mult).into();
            logup.write_frac(eval, Fraction::new(numerator, denom));
        }
        logup.finalize(eval);
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::program::iter_program_steps,
    };

    use super::*;

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        #[rustfmt::skip]
        let basic_block = BasicBlock::new(vec![
            // 0b11100 & 0b01010 = 0b01000
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 28, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 8, InstructionType::IType),
            // x3 = x1 & x2
            Instruction::new(Opcode::from(BuiltinOpcode::AND), 3, 1, 2, InstructionType::RType),

            // 0b100010 | 0b011011 = 0b111011
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 34, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 27, InstructionType::IType),
            // x6 = x4 | x5
            Instruction::new(Opcode::from(BuiltinOpcode::OR), 6, 4, 5, InstructionType::RType),

            // 0b1100101 ^ 0b1010001 = 0b0110100
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 101, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 81, InstructionType::IType),
            // x9 = x7 ^ x8
            Instruction::new(Opcode::from(BuiltinOpcode::XOR), 9, 7, 8, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_values() {
        type Chips = (CpuChip, AddChip, BitOpChip, RegisterMemCheckChip);
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let mut traces = Traces::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut side_note = SideNote::default();

        for (row_idx, program_step) in program_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }

        let and_vals = traces
            .column(2, ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(and_vals);

        assert_eq!(output, 0b1000);

        let or_vals = traces
            .column(5, ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(or_vals);

        assert_eq!(output, 0b111011);

        let xor_vals = traces
            .column(8, ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(xor_vals);

        assert_eq!(output, 0b0110100);

        assert_chip::<Chips>(traces, None);
    }
}
