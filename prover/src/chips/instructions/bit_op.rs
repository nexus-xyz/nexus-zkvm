use std::array;

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow, Relation, RelationEntry},
    core::{
        backend::simd::m31::{PackedBaseField, LOG_N_LANES},
        fields::m31::BaseField,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{
        self, IsAnd, IsOr, IsXor, ValueA, ValueA4_7, ValueB, ValueB4_7, ValueC, ValueC4_7,
    },
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
    virtual_column::{VirtualColumn, VirtualColumnForSum},
};

// Support bitwise operations opcode with lookups.
pub struct BitOpChip;

const LOOKUP_TUPLE_SIZE: usize = 4; // op_flag, b, c, a
stwo_prover::relation!(BitOpLookupElements, LOOKUP_TUPLE_SIZE);

/// Unit-enum indicating which bitwise operation is executed by the chip.
///
/// Note that its numeric value is used as the first element in the tuple to enforce the
/// difference between lookups. Otherwise, the verifier can't differentiate between
/// (is_and, is_or) == (one(), zero()) and (is_and, is_or) == (zero(), one()) for the
/// same denominator in the logup fraction.
#[derive(Debug, Copy, Clone)]
pub(crate) enum BitOp {
    And = 1,
    Or = 2,
    Xor = 3,
}

impl BitOp {
    /// Converts an operation flag into a field element.
    pub(crate) fn to_base_field(self) -> BaseField {
        BaseField::from(self as u32)
    }

    /// Converts an operation flag into a SIMD vector of repeating elements.
    pub(crate) fn to_packed_base_field(self) -> PackedBaseField {
        PackedBaseField::broadcast((self as u32).into())
    }
}

/// A virtual column containing the lower four bits of each limb of ValueA
struct ValueA0_3;

impl VirtualColumn<WORD_SIZE> for ValueA0_3 {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; WORD_SIZE] {
        let value_a: [_; WORD_SIZE] = traces.column(row_idx, ValueA);
        let value_a_4_7: [_; WORD_SIZE] = traces.column(row_idx, ValueA4_7);
        let mut result = [BaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_a[i] - value_a_4_7[i] * BaseField::from(1 << 4);
        }
        result
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; WORD_SIZE] {
        let value_a = traces.get_base_column::<WORD_SIZE>(ValueA);
        let value_a_4_7 = traces.get_base_column::<WORD_SIZE>(ValueA4_7);
        let mut result = [PackedBaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_a[i].data[vec_idx]
                - value_a_4_7[i].data[vec_idx]
                    * PackedBaseField::broadcast(BaseField::from(1 << 4));
        }
        result
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; WORD_SIZE] {
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_a_4_7 = trace_eval!(trace_eval, ValueA4_7);
        array::from_fn(|i| {
            value_a[i].clone() - value_a_4_7[i].clone() * E::F::from(BaseField::from(1 << 4))
        })
    }
}

/// A virtual column containing the lower four bits of each limb of ValueB
struct ValueB0_3;

impl VirtualColumn<WORD_SIZE> for ValueB0_3 {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; WORD_SIZE] {
        let value_b: [_; WORD_SIZE] = traces.column(row_idx, ValueB);
        let value_b_4_7: [_; WORD_SIZE] = traces.column(row_idx, ValueB4_7);
        let mut result = [BaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_b[i] - value_b_4_7[i] * BaseField::from(1 << 4);
        }
        result
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; WORD_SIZE] {
        let value_b = traces.get_base_column::<WORD_SIZE>(ValueB);
        let value_b_4_7 = traces.get_base_column::<WORD_SIZE>(ValueB4_7);
        let mut result = [PackedBaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_b[i].data[vec_idx]
                - value_b_4_7[i].data[vec_idx]
                    * PackedBaseField::broadcast(BaseField::from(1 << 4));
        }
        result
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; WORD_SIZE] {
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_b_4_7 = trace_eval!(trace_eval, ValueB4_7);
        array::from_fn(|i| {
            value_b[i].clone() - value_b_4_7[i].clone() * E::F::from(BaseField::from(1 << 4))
        })
    }
}

/// A virtual column containing the lower four bits of each limb of ValueC
struct ValueC0_3;

impl VirtualColumn<WORD_SIZE> for ValueC0_3 {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; WORD_SIZE] {
        let value_c: [_; WORD_SIZE] = traces.column(row_idx, ValueC);
        let value_c_4_7: [_; WORD_SIZE] = traces.column(row_idx, ValueC4_7);
        let mut result = [BaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_c[i] - value_c_4_7[i] * BaseField::from(1 << 4);
        }
        result
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; WORD_SIZE] {
        let value_c = traces.get_base_column::<WORD_SIZE>(ValueC);
        let value_c_4_7 = traces.get_base_column::<WORD_SIZE>(ValueC4_7);
        let mut result = [PackedBaseField::zero(); WORD_SIZE];
        for i in 0..WORD_SIZE {
            result[i] = value_c[i].data[vec_idx]
                - value_c_4_7[i].data[vec_idx]
                    * PackedBaseField::broadcast(BaseField::from(1 << 4));
        }
        result
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; WORD_SIZE] {
        let value_c = trace_eval!(trace_eval, ValueC);
        let value_c_4_7 = trace_eval!(trace_eval, ValueC4_7);
        array::from_fn(|i| {
            value_c[i].clone() - value_c_4_7[i].clone() * E::F::from(BaseField::from(1 << 4))
        })
    }
}

pub struct ExecutionResult {
    out_bytes: Word,
    bit_op: BitOp,
    value_a_4_7: Word,
    value_b_0_3: Word,
    value_b_4_7: Word,
    value_c_0_3: Word,
    value_c_4_7: Word,
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

        let (_value_a_0_3, value_a_4_7) = split_limbs(&value_a);
        let (value_b_0_3, value_b_4_7) = split_limbs(&value_b);
        let (value_c_0_3, value_c_4_7) = split_limbs(&value_c);

        ExecutionResult {
            out_bytes: value_a,
            bit_op,
            value_a_4_7,
            value_b_0_3,
            value_b_4_7,
            value_c_0_3,
            value_c_4_7,
        }
    }
}

/// Splits each 8-bit limb of a word into two 4-bit components. The results are combined back into two words (less-significant, more-significant).
fn split_limbs(word: &Word) -> (Word, Word) {
    let mut less_significant = Word::default();
    let mut more_significant = Word::default();
    for i in 0..WORD_SIZE {
        less_significant[i] = word[i] & 0b1111;
        more_significant[i] = word[i] >> 4;
    }
    (less_significant, more_significant)
}

pub struct IsBitop;

impl VirtualColumnForSum for IsBitop {
    fn columns() -> &'static [Column] {
        &[IsAnd, IsOr, IsXor]
    }
}

impl MachineChip for BitOpChip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
        _config: &ExtensionsConfig,
    ) {
        all_elements.insert(BitOpLookupElements::draw(channel));
    }

    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        _config: &ExtensionsConfig,
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

        let ExecutionResult {
            out_bytes,
            bit_op,
            value_a_4_7,
            value_b_0_3,
            value_b_4_7,
            value_c_0_3,
            value_c_4_7,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        assert_eq!(
            out_bytes,
            vm_step
                .get_result()
                .expect("Bitwise instruction must have a result")
        );

        // Fill 4-bit splittings
        traces.fill_columns(row_idx, value_a_4_7, ValueA4_7);
        traces.fill_columns(row_idx, value_b_4_7, ValueB4_7);
        traces.fill_columns(row_idx, value_c_4_7, ValueC4_7);

        let multiplicity_counter = match bit_op {
            BitOp::And => &mut side_note.bit_op.multiplicity_and,
            BitOp::Or => &mut side_note.bit_op.multiplicity_or,
            BitOp::Xor => &mut side_note.bit_op.multiplicity_xor,
        };
        for limb_idx in 0..WORD_SIZE {
            // The tuple (b, c, b ^ c) is located at row_idx b * 16 + c. This is due to nested 0..16 loops.
            // Increment Multiplicity(And/Or/Xor)[b0_3[i] * 16 + c0_3[i]]
            let looked_up_row = value_b_0_3[limb_idx] * 16 + value_c_0_3[limb_idx];
            *multiplicity_counter.entry(looked_up_row).or_default() += 1;
            // Increment Multiplicity(And/Or/Xor)[b4_7[i] * 16 + c4_7[i]]
            let looked_up_row = value_b_4_7[limb_idx] * 16 + value_c_4_7[limb_idx];
            *multiplicity_counter.entry(looked_up_row).or_default() += 1;
        }

        traces.fill_columns(row_idx, out_bytes, ValueA);
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen rows.
    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        _preprocessed_trace: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &BitOpLookupElements = lookup_element.as_ref();
        // Add checked pairs to logup sum
        let [is_and] = original_traces.get_base_column(IsAnd);
        let [is_or] = original_traces.get_base_column(IsOr);
        let [is_xor] = original_traces.get_base_column(IsXor);
        let value_a_4_7: [_; WORD_SIZE] = original_traces.get_base_column(ValueA4_7);
        let value_b_4_7: [_; WORD_SIZE] = original_traces.get_base_column(ValueB4_7);
        let value_c_4_7: [_; WORD_SIZE] = original_traces.get_base_column(ValueC4_7);
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
                    let checked_a =
                        ValueA0_3::read_from_finalized_traces(original_traces, vec_row)[limb_idx];
                    let checked_b =
                        ValueB0_3::read_from_finalized_traces(original_traces, vec_row)[limb_idx];
                    let checked_c =
                        ValueC0_3::read_from_finalized_traces(original_traces, vec_row)[limb_idx];
                    let checked_tuple = vec![op_type, checked_b, checked_c, checked_a];
                    let denom = lookup_element.combine(&checked_tuple);
                    let numerator = is_op.data[vec_row];
                    logup_col_gen.write_frac(vec_row, numerator.into(), denom);
                }
                logup_col_gen.finalize_col();
                let mut logup_col_gen = logup_trace_gen.new_col();
                // vec_row is row_idx divided by 16. Because SIMD.
                for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
                    let op_type = op_type.to_packed_base_field();
                    let checked_a = value_a_4_7[limb_idx].data[vec_row];
                    let checked_b = value_b_4_7[limb_idx].data[vec_row];
                    let checked_c = value_c_4_7[limb_idx].data[vec_row];
                    let checked_tuple = vec![op_type, checked_b, checked_c, checked_a];
                    let denom = lookup_element.combine(&checked_tuple);
                    let numerator = is_op.data[vec_row];
                    logup_col_gen.write_frac(vec_row, numerator.into(), denom);
                }
                logup_col_gen.finalize_col();
            }
        }
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let lookup_elements: &BitOpLookupElements = lookup_elements.as_ref();

        // Constrain four-bit components. Note that the four-bit components do not need separate range-checks because the bit-op lookup tables only contain in-range entries.
        let value_a4_7 = trace_eval!(trace_eval, ValueA4_7);
        let value_b4_7 = trace_eval!(trace_eval, ValueB4_7);
        let value_c4_7 = trace_eval!(trace_eval, ValueC4_7);

        // Constrain logup

        // Add checked occurrences to logup sum
        let [is_and] = trace_eval!(trace_eval, IsAnd);
        let [is_or] = trace_eval!(trace_eval, IsOr);
        let [is_xor] = trace_eval!(trace_eval, IsXor);
        for limb_idx in 0..WORD_SIZE {
            for (op_type, is_op) in [
                (BitOp::And, &is_and),
                (BitOp::Or, &is_or),
                (BitOp::Xor, &is_xor),
            ] {
                let op_type = E::F::from(op_type.to_base_field());
                let numerator: E::EF = is_op.clone().into();
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    numerator,
                    &[
                        op_type.clone(),
                        ValueB0_3::eval(trace_eval)[limb_idx].clone(),
                        ValueC0_3::eval(trace_eval)[limb_idx].clone(),
                        ValueA0_3::eval(trace_eval)[limb_idx].clone(),
                    ],
                ));

                let numerator: E::EF = is_op.clone().into();
                eval.add_to_relation(RelationEntry::new(
                    lookup_elements,
                    numerator,
                    &[
                        op_type,
                        value_b4_7[limb_idx].clone(),
                        value_c4_7[limb_idx].clone(),
                        value_a4_7[limb_idx].clone(),
                    ],
                ));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip},
        extensions::{bit_op::BitOpMultiplicityEval, final_reg::FinalRegEval, ExtensionComponent},
        test_utils::assert_chip,
        trace::{
            preprocessed::PreprocessedBuilder,
            program::iter_program_steps,
            program_trace::{ProgramTraceRef, ProgramTracesBuilder},
        },
    };

    use super::*;

    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use stwo_prover::core::fields::qm31::SecureField;

    const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // 0b11100 & 0b01000 = 0b01000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 8),
            // x3 = x1 & x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AND), 3, 1, 2),
            // 0b100010 | 0b011011 = 0b111011
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 34),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 27),
            // x6 = x4 | x5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 6, 4, 5),
            // 0b1100101 ^ 0b1010001 = 0b0110100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 101),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 8, 0, 81),
            // x9 = x7 ^ x8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::XOR), 9, 7, 8),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_values() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            BitOpChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_trace_ref = ProgramTraceRef::new_with_empty_memory(program_info);
        let program_trace = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_trace, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
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

        let (lookup_elements, claimed_sum_1) =
            assert_chip::<Chips>(traces, Some(program_trace.finalize()));

        // verify that logup sums match
        let ext = ExtensionComponent::bit_op_multiplicity();

        let component_trace = ext.generate_component_trace(
            BitOpMultiplicityEval::LOG_SIZE,
            program_trace_ref,
            &mut side_note,
        );
        let (_, claimed_sum_2) =
            ext.generate_interaction_trace(component_trace, &side_note, &lookup_elements);

        let ext = ExtensionComponent::final_reg();
        let component_trace =
            ext.generate_component_trace(FinalRegEval::LOG_SIZE, program_trace_ref, &mut side_note);
        let (_, claimed_sum_3) =
            ext.generate_interaction_trace(component_trace, &side_note, &lookup_elements);
        assert_eq!(
            claimed_sum_1 + claimed_sum_2 + claimed_sum_3,
            SecureField::zero()
        );
    }
}
