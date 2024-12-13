use num_traits::{One, Zero};

use nexus_vm::WORD_SIZE;
use stwo_prover::{
    constraint_framework::{
        logup::{LogupAtRow, LogupTraceGenerator, LookupElements},
        EvalAtRow, INTERACTION_TRACE_IDX,
    },
    core::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    column::{Column, PreprocessedColumn},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        utils::FromBaseFields,
        PreprocessedTraces, ProgramStep, Traces,
    },
    traits::MachineChip,
};

/// A Chip for program memory checking
///
/// ProgMemCheckChip needs to be located after CpuChip

pub struct ProgramMemCheckChip;

impl MachineChip for ProgramMemCheckChip {
    /// Fills `ProgPrevCtr` columns
    ///
    /// Assumes other chips have written to `Pc` on the current row
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
    ) {
        if let Some(_vm_step) = vm_step {
            // not padding
            let pc = traces.column(row_idx, Column::Pc);
            let pc = u32::from_base_fields(pc);
            let last_access_counter = side_note
                .program_mem_check
                .last_access_counter
                .get(&pc)
                .unwrap_or(&0u32);
            traces.fill_columns(row_idx, *last_access_counter, Column::ProgCtrPrev);
            let new_access_counter = last_access_counter
                .checked_add(1)
                .expect("access counter overflow");
            traces.fill_columns(row_idx, new_access_counter, Column::ProgCtrCur);
            // Compute and fill carry flags
            let last_counter_bytes = last_access_counter.to_le_bytes();
            let mut carry_bits = [false; WORD_SIZE];
            let mut incremented_bytes = [0u8; WORD_SIZE];
            (incremented_bytes[0], carry_bits[0]) = last_counter_bytes[0].overflowing_add(1);
            for i in 1..WORD_SIZE {
                // Add the bytes and the previous carry
                (incremented_bytes[i], carry_bits[i]) =
                    last_counter_bytes[i].overflowing_add(carry_bits[i - 1] as u8);
            }
            assert!(!carry_bits[WORD_SIZE - 1]); // Check against overflow
            assert_eq!(u32::from_le_bytes(incremented_bytes), new_access_counter);
            traces.fill_columns(row_idx, carry_bits, Column::ProgCtrCarry);
            side_note
                .program_mem_check
                .last_access_counter
                .insert(pc, new_access_counter);
            // Note: no need to udpate the access counter for pc + {1,2,3}. They are not used.
            let instruction_word = traces.column(row_idx, Column::InstrVal);
            let instruction_word = u32::from_base_fields(instruction_word);
            let known_instruction_word = side_note
                .program_mem_check
                .accessed_program_memory
                .insert(pc, instruction_word);
            known_instruction_word
                .and_then(|known_word| Some(assert_eq!(known_word, instruction_word)));
        }
        // Use accessed_program_memory sidenote to fill in the final program memory contents
        if row_idx == traces.num_rows() - 1 {
            assert!(
                side_note.program_mem_check.accessed_program_memory.len() <= 1 << traces.log_size(),
                "More Pc access than the size of trace, unexpected."
            );
            let mut final_program_row_idx: usize = 0;
            for (pc, instruction_word) in side_note.program_mem_check.accessed_program_memory.iter()
            {
                traces.fill_columns(final_program_row_idx, *pc, Column::PrgMemoryPc);
                traces.fill_columns(
                    final_program_row_idx,
                    *instruction_word,
                    Column::PrgMemoryWord,
                );
                let counter = side_note
                    .program_mem_check
                    .last_access_counter
                    .get(pc)
                    .expect("counter not found with an accessed Pc");
                traces.fill_columns(final_program_row_idx, *counter, Column::FinalPrgMemoryCtr);
                traces.fill_columns(final_program_row_idx, true, Column::PrgMemoryFlag);
                final_program_row_idx += 1;
            }
        }
    }

    /// Fills the interaction trace for the program memory checking
    ///
    /// The interaction trace adds up the following fractions. The whole sum will be constrained to be zero.
    ///
    /// For the initial content of the program memory:
    /// * 1 / lookup_element.combine(tuple) is added for each instruction
    /// where tuples contain (the address, the whole word of the instruction, 0u32).
    ///
    /// On each program memory access:
    /// * 1 / lookup_element.combine(tuple_old) is subtracted
    /// * 1 / lookup_element.combine(tuple_new) is added
    /// where tuples contain (the address, the whole word of the instruction, counter value).
    /// The counter value is incremented by one on each access.
    ///
    /// For the final content of the program memory:
    /// * 1 / lookup_element.combine(tuple) is subtracted for each instruction
    /// where tuples contain (the address, the whole word of the instruction, final counter value).
    fn fill_interaction_trace(
        original_traces: &Traces,
        _preprocessed_trace: &PreprocessedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());
        // add initial digest
        // For every used Pc, a tuple (address, instruction_as_word, 0u32) is added.
        Self::add_initial_digest(&mut logup_trace_gen, original_traces, lookup_element);

        // subtract final digest
        // For every used Pc, a tuple (address, instruction_as_word, final_counter) is subtracted.
        Self::subtract_final_digest(&mut logup_trace_gen, original_traces, lookup_element);

        // subtract program memory access, previous counter reads
        // For each access, a tuple of the form (address, instruction_as_word, previous_couter) is subtracted.
        Self::subtract_access(&mut logup_trace_gen, original_traces, lookup_element);

        // add program memory access, new counter write backs
        // For each access, a tuple of the form (address, instruction_as_word, new_counter) is added.
        Self::add_access(&mut logup_trace_gen, original_traces, lookup_element);
        let (ret, total_sum) = logup_trace_gen.finalize_last();
        assert_eq!(total_sum, SecureField::zero());
        ret
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let _ = lookup_elements;
        // Constrain PrgCurCtr = PrgPrevCtr + 1
        let [is_padding] = trace_eval.column_eval(Column::IsPadding);
        let prg_prev_ctr = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrPrev);
        let prg_cur_ctr = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrCur);
        let prg_ctr_carry = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrCarry);
        let modulus = E::F::from((1u32 << 8).into());
        for i in 0..WORD_SIZE {
            let carry = i
                .checked_sub(1)
                .map(|j| prg_ctr_carry[j].clone())
                .unwrap_or(E::F::one());

            // prg_cur_ctr[i] + prg_ctr_carry[i] * 2^8 = prg_prev_ctr[i] + h1[i - 1] (or 1 if i == 0)
            eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (prg_cur_ctr[i].clone() + prg_ctr_carry[i].clone() * modulus.clone()
                        - (prg_prev_ctr[i].clone() + carry)),
            );
        }
        // Don't allow overflow
        eval.add_constraint(prg_ctr_carry[WORD_SIZE - 1].clone());
        // Logup constraints
        let [is_first] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);
        // add initial digest
        // For each used Pc, oen tuple (address, instruction_as_word, 0u32) is added.
        Self::constrain_add_initial_digest(&mut logup, eval, trace_eval, lookup_elements);

        // subtract final digest
        // For each used Pc, one tuple (address, instruction_as_word, final_counter) is subtracted.
        Self::constrain_subtract_final_digest(&mut logup, eval, trace_eval, lookup_elements);

        // subtract program memory access, previous counter reads
        // For each access, one tuple (address, instruction_as_word, previous_couter) is subtracted.
        Self::constrain_subtract_access(&mut logup, eval, trace_eval, lookup_elements);

        // add program memory access, new counter write backs
        // For each access, one tuple (address, instruction_as_word, new_counter) is added.
        Self::constrain_add_access(&mut logup, eval, trace_eval, lookup_elements);

        logup.finalize(eval);
    }
}

impl ProgramMemCheckChip {
    /// Fills the interaction trace columns for adding the initial content of the program memory:
    /// * 1 / lookup_element.combine(tuple) is added for each instruction
    /// where tuples contain (the address, the whole word of the instruction, 0u32).
    ///
    /// The initial content of the memory is located on rows where PrgMemoryFlag is 1.
    fn add_initial_digest(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [prg_memory_flag] = original_traces.get_base_column(Column::PrgMemoryFlag);
        let prg_memory_pc = original_traces.get_base_column::<WORD_SIZE>(Column::PrgMemoryPc);
        let prg_memory_word = original_traces.get_base_column::<WORD_SIZE>(Column::PrgMemoryWord);
        // The counter is not used because initially the counters are zero.
        let mut logup_col_gen = logup_trace_gen.new_col();
        // Add (Pc, prg_memory_word, 0u32)
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for prg_memory_pc_byte in prg_memory_pc.iter() {
                tuple.push(prg_memory_pc_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), WORD_SIZE);
            for prg_memory_byte in prg_memory_word.iter() {
                tuple.push(prg_memory_byte.data[vec_row]);
            }
            // Initial counter is zero
            tuple.extend_from_slice(&[PackedBaseField::zero(); WORD_SIZE]);
            assert_eq!(tuple.len(), WORD_SIZE + WORD_SIZE + WORD_SIZE);
            let numerator = prg_memory_flag.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                numerator.into(),
                lookup_element.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    /// Adds logup constraints for adding up fractions in `add_initial_digest()`
    ///
    /// `add_initial_digest()` and `constrain_add_initial_digest()` must be in sync, the same way with all stwo logup usage.
    fn constrain_add_initial_digest<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [prg_memory_flag] = trace_eval!(trace_eval, Column::PrgMemoryFlag);
        let prg_memory_pc = trace_eval!(trace_eval, Column::PrgMemoryPc);
        let prg_memory_word = trace_eval!(trace_eval, Column::PrgMemoryWord);
        // Add (Pc, prg_memory_word, 0u32)
        let mut tuple = vec![];
        for prg_memory_pc_byte in prg_memory_pc.into_iter() {
            tuple.push(prg_memory_pc_byte);
        }
        assert_eq!(tuple.len(), WORD_SIZE);
        for prg_memory_byte in prg_memory_word.into_iter() {
            tuple.push(prg_memory_byte);
        }
        for _ in 0..WORD_SIZE {
            tuple.extend_from_slice(&[E::F::zero()]);
        }
        assert_eq!(tuple.len(), 3 * WORD_SIZE);
        let numerator = prg_memory_flag;
        logup.write_frac(
            eval,
            Fraction::new(numerator.into(), lookup_elements.combine(tuple.as_slice())),
        );
    }

    /// For the final content of the program memory, subtract in the interaction trace:
    /// * 1 / lookup_element.combine(tuple) for each instruction
    /// where tuples contain (the address, the whole word of the instruction, final counter value).
    ///
    /// The information about the final content of the program memory is located on rows with PrgMemoryFlag set to 1.
    /// Most columns are the same as the initial program memory content.
    /// The final counter is located on the FinalPrgMemoryCtr column.
    fn subtract_final_digest(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [prg_memory_flag] = original_traces.get_base_column(Column::PrgMemoryFlag);
        let prg_memory_pc = original_traces.get_base_column::<WORD_SIZE>(Column::PrgMemoryPc);
        let prg_memory_word = original_traces.get_base_column::<WORD_SIZE>(Column::PrgMemoryWord);
        let prg_memory_ctr =
            original_traces.get_base_column::<WORD_SIZE>(Column::FinalPrgMemoryCtr);
        let mut logup_col_gen = logup_trace_gen.new_col();
        // Subtract (Pc, prg_memory_word, 0u32)
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for prg_memory_pc_byte in prg_memory_pc.iter() {
                tuple.push(prg_memory_pc_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), WORD_SIZE);
            for prg_memory_byte in prg_memory_word.iter() {
                tuple.push(prg_memory_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE);
            for prg_memory_ctr_byte in prg_memory_ctr.iter() {
                tuple.push(prg_memory_ctr_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 3 * WORD_SIZE);
            let numerator = prg_memory_flag.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                (-numerator).into(),
                lookup_element.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    /// Adds logup constraints for subtracting fractions in `subtract_final_digest()`
    ///
    /// `subtract_final_digest()` and `constrain_subtract_final_digest()` must be in sync, the same way with all stwo logup usage.
    fn constrain_subtract_final_digest<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [prg_memory_flag] = trace_eval!(trace_eval, Column::PrgMemoryFlag);
        let prg_memory_pc = trace_eval!(trace_eval, Column::PrgMemoryPc);
        let prg_memory_word = trace_eval!(trace_eval, Column::PrgMemoryWord);
        let prg_memory_ctr = trace_eval!(trace_eval, Column::FinalPrgMemoryCtr);
        let mut tuple = vec![];
        for prg_memory_pc_byte in prg_memory_pc.into_iter() {
            tuple.push(prg_memory_pc_byte);
        }
        assert_eq!(tuple.len(), WORD_SIZE);
        for prg_memory_byte in prg_memory_word.into_iter() {
            tuple.push(prg_memory_byte);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE);
        for prg_memory_ctr_byte in prg_memory_ctr.into_iter() {
            tuple.push(prg_memory_ctr_byte);
        }
        assert_eq!(tuple.len(), 3 * WORD_SIZE);
        let numerator = prg_memory_flag;
        logup.write_frac(
            eval,
            Fraction::new(
                (-numerator).into(),
                lookup_elements.combine(tuple.as_slice()),
            ),
        );
    }

    /// On each program memory access:
    /// * 1 / lookup_element.combine(tuple_old) is subtracted
    /// where tuples contain (the address, the whole word of the instruction, previous counter value).
    ///
    /// The numerator is zero on the padding rows, so that the row doesn't contribute to the logup sum.
    fn subtract_access(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_padding] = original_traces.get_base_column(Column::IsPadding);
        let prg_prev_ctr = original_traces.get_base_column::<WORD_SIZE>(Column::ProgCtrPrev);
        let pc = original_traces.get_base_column::<WORD_SIZE>(Column::Pc);
        let instruction_word = original_traces.get_base_column::<WORD_SIZE>(Column::InstrVal);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for pc_byte in pc.iter() {
                tuple.push(pc_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), WORD_SIZE);
            for instruction_byte in instruction_word.iter() {
                tuple.push(instruction_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE);
            for prg_prev_ctr_byte in prg_prev_ctr.iter() {
                tuple.push(prg_prev_ctr_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 3 * WORD_SIZE);
            let numerator = PackedBaseField::one() - is_padding.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                (-numerator).into(),
                lookup_element.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    /// Adds logup constraints for subtracting fractions in `subtract_access()`
    ///
    /// `subtract_access()` and `constrain_subtract_access()` must be in sync, the same way with all stwo logup usage.
    fn constrain_subtract_access<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_padding] = trace_eval!(trace_eval, Column::IsPadding);
        let prg_prev_ctr = trace_eval!(trace_eval, Column::ProgCtrPrev);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let instruction_word = trace_eval!(trace_eval, Column::InstrVal);
        let mut tuple = vec![];
        for pc_byte in pc.into_iter() {
            tuple.push(pc_byte);
        }
        assert_eq!(tuple.len(), WORD_SIZE);
        for instruction_byte in instruction_word.into_iter() {
            tuple.push(instruction_byte);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE);
        for prg_prev_ctr_byte in prg_prev_ctr.into_iter() {
            tuple.push(prg_prev_ctr_byte);
        }
        assert_eq!(tuple.len(), 3 * WORD_SIZE);
        let numerator = E::F::one() - is_padding;
        logup.write_frac(
            eval,
            Fraction::new(
                (-numerator).into(),
                lookup_elements.combine(tuple.as_slice()),
            ),
        );
    }

    /// On each program memory access:
    /// * 1 / lookup_element.combine(tuple_new) is added
    /// where tuples contain (the address, the whole word of the instruction, current counter value).
    /// The counter value is incremented by one on each access.
    ///
    /// The numerator is zero when the row is padding, so that the row doesn't contribute to the logup sum.
    fn add_access(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &Traces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_padding] = original_traces.get_base_column(Column::IsPadding);
        let prg_cur_ctr = original_traces.get_base_column::<WORD_SIZE>(Column::ProgCtrCur);
        let pc = original_traces.get_base_column::<WORD_SIZE>(Column::Pc);
        let instruction_word = original_traces.get_base_column::<WORD_SIZE>(Column::InstrVal);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for pc_byte in pc.iter() {
                tuple.push(pc_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), WORD_SIZE);
            for instruction_byte in instruction_word.iter() {
                tuple.push(instruction_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE);
            for prg_prev_ctr_byte in prg_cur_ctr.iter() {
                tuple.push(prg_prev_ctr_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 3 * WORD_SIZE);
            let numerator = PackedBaseField::one() - is_padding.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                numerator.into(),
                lookup_element.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    /// Adds logup constraints for adding fractions in `add_access()`
    ///
    /// `add_access()` and `constrain_add_access()` must be in sync, the same way with all stwo logup usage.
    fn constrain_add_access<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_padding] = trace_eval!(trace_eval, Column::IsPadding);
        let prg_cur_ctr = trace_eval!(trace_eval, Column::ProgCtrCur);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let instruction_word = trace_eval!(trace_eval, Column::InstrVal);
        let mut tuple = vec![];
        for pc_byte in pc.into_iter() {
            tuple.push(pc_byte);
        }
        assert_eq!(tuple.len(), WORD_SIZE);
        for instruction_byte in instruction_word.into_iter() {
            tuple.push(instruction_byte);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE);
        for prg_prev_ctr_byte in prg_cur_ctr.into_iter() {
            tuple.push(prg_prev_ctr_byte);
        }
        assert_eq!(tuple.len(), 3 * WORD_SIZE);
        let numerator = E::F::one() - is_padding;
        logup.write_frac(
            eval,
            Fraction::new(numerator.into(), lookup_elements.combine(tuple.as_slice())),
        );
    }
}
#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip},
        test_utils::assert_chip,
        trace::{utils::IntoBaseFields, PreprocessedTraces},
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    // PreprocessedTraces::MIN_LOG_SIZE makes the test consume more than 40 seconds.
    const LOG_SIZE: u32 = 10;

    #[rustfmt::skip]
    fn setup_basic_block_ir() -> Vec<BasicBlock>
    {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_prog_mem_check_add_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();

        let program_steps = vm_traces.blocks.into_iter().map(|block| {
            let regs = block.regs;
            assert_eq!(block.steps.len(), 1);
            Some(ProgramStep {
                regs,
                step: block.steps[0].clone(),
            })
        });
        let num_steps = program_steps.clone().count();
        assert_eq!(num_steps, basic_block[0].len());
        let trace_steps = program_steps
            .chain(std::iter::repeat(None))
            .take(traces.num_rows());

        for (row_idx, program_step) in trace_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            CpuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

            // Fill in the main trace of the ProgMemCheckChip
            ProgramMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
            );

            // Fill in the main trace of the AddChip
            AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }

        for i in 0..num_steps {
            assert_eq!(
                traces.column(i, Column::ProgCtrPrev),
                0u32.into_base_fields()
            );
            assert_eq!(
                traces.column(i, Column::ProgCtrCur),
                1u32.into_base_fields()
            );
            assert_eq!(
                traces.column(i, Column::ProgCtrCarry),
                [0u8; WORD_SIZE].into_base_fields()
            );
        }
        for item in side_note.program_mem_check.last_access_counter.iter() {
            assert_eq!(*item.1, 1, "unexpected number of accesses to Pc");
        }
        let preprocessed_column = PreprocessedTraces::empty(LOG_SIZE);
        assert_chip::<ProgramMemCheckChip>(traces, Some(preprocessed_column));
    }
}
