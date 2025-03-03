use nexus_common::constants::WORD_SIZE_HALVED;
use num_traits::{One, Zero};

use nexus_vm::WORD_SIZE;
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow, Relation, RelationEntry},
    core::{
        backend::simd::m31::{PackedBaseField, LOG_N_LANES},
        fields::m31::BaseField,
    },
};

use crate::{
    column::{Column, PreprocessedColumn, ProgramColumn},
    components::AllLookupElements,
    trace::{
        eval::{preprocessed_trace_eval, program_trace_eval, trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        utils::FromBaseFields,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

/// A Chip for program memory checking
///
/// ProgMemCheckChip needs to be located after CpuChip
pub struct ProgramMemCheckChip;

const LOOKUP_TUPLE_SIZE: usize = 3 * WORD_SIZE;
stwo_prover::relation!(ProgramCheckLookupElements, LOOKUP_TUPLE_SIZE);

impl MachineChip for ProgramMemCheckChip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        all_elements.insert(ProgramCheckLookupElements::draw(channel));
    }

    /// Fills `ProgPrevCtr` columns
    ///
    /// Assumes other chips have written to `Pc` on the current row
    fn fill_main_trace(
        traces: &mut TracesBuilder,
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
            traces.fill_columns(
                row_idx,
                [carry_bits[1], carry_bits[3]],
                Column::ProgCtrCarry,
            );
            side_note
                .program_mem_check
                .last_access_counter
                .insert(pc, new_access_counter);
        }
        // Use accessed_program_memory sidenote to fill in the final program memory contents
        if row_idx == traces.num_rows() - 1 {
            for (pc, counter) in side_note.program_mem_check.last_access_counter.iter() {
                let traget_row_idx = side_note
                    .program_mem_check
                    .find_row_idx(*pc)
                    .expect("Pc not found in program trace");
                traces.fill_columns(traget_row_idx, *counter, Column::FinalPrgMemoryCtr);
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
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        _preprocessed_trace: &PreprocessedTraces,
        program_trace: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &ProgramCheckLookupElements = lookup_element.as_ref();
        // add initial digest
        // For every used Pc, a tuple (address, instruction_as_word, 0u32) is added.
        Self::add_initial_digest(
            logup_trace_gen,
            original_traces,
            program_trace,
            lookup_element,
        );

        // subtract final digest
        // For every used Pc, a tuple (address, instruction_as_word, final_counter) is subtracted.
        Self::subtract_final_digest(
            logup_trace_gen,
            original_traces,
            program_trace,
            lookup_element,
        );

        // subtract program memory access, previous counter reads
        // For each access, a tuple of the form (address, instruction_as_word, previous_couter) is subtracted.
        Self::subtract_access(logup_trace_gen, original_traces, lookup_element);

        // add program memory access, new counter write backs
        // For each access, a tuple of the form (address, instruction_as_word, new_counter) is added.
        Self::add_access(logup_trace_gen, original_traces, lookup_element);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
    ) {
        let lookup_elements: &ProgramCheckLookupElements = lookup_elements.as_ref();
        // Constrain the program counter on the first row
        let pc = trace_eval!(trace_eval, Column::Pc);
        let [is_first] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        let initial_pc = program_trace_eval!(trace_eval, ProgramColumn::PrgInitialPc);
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                is_first.clone() * (pc[limb_idx].clone() - initial_pc[limb_idx].clone()),
            );
        }

        // Constrain PrgCurCtr = PrgPrevCtr + 1
        let [is_padding] = trace_eval.column_eval(Column::IsPadding);
        let prg_prev_ctr = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrPrev);
        let prg_cur_ctr = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrCur);
        let prg_ctr_carry = trace_eval.column_eval::<WORD_SIZE_HALVED>(Column::ProgCtrCarry);
        let modulus = E::F::from((1u32 << 8).into());

        // prg_cur_ctr[0] + prg_cur_ctr[1] * 256 + prg_ctr_carry[0] * 2^{16} = (prg_prev_ctr[0] + prg_prev_ctr[1] * 256) + 1
        eval.add_constraint(
            (E::F::one() - is_padding.clone())
                * (prg_cur_ctr[0].clone()
                    + prg_cur_ctr[1].clone() * modulus.clone()
                    + prg_ctr_carry[0].clone() * E::F::from(BaseField::from(1 << 16))
                    - (prg_prev_ctr[0].clone()
                        + prg_prev_ctr[1].clone() * modulus.clone()
                        + E::F::one())),
        );

        // prg_cur_ctr[2] + prg_cur_ctr[3] * 256 + prg_ctr_carry[1] * 2^{16} = prg_prev_ctr[2] + prg_prev_ctr[3] * 256 + prg_ctr_carry[1]
        eval.add_constraint(
            (E::F::one() - is_padding.clone())
                * (prg_cur_ctr[2].clone()
                    + prg_cur_ctr[3].clone() * modulus.clone()
                    + prg_ctr_carry[1].clone() * E::F::from(BaseField::from(1 << 16))
                    - (prg_prev_ctr[2].clone()
                        + prg_prev_ctr[3].clone() * modulus.clone()
                        + prg_ctr_carry[0].clone())),
        );

        // Don't allow overflow
        eval.add_constraint(prg_ctr_carry[WORD_SIZE_HALVED - 1].clone());
        // Logup constraints

        // add initial digest
        // For each used Pc, oen tuple (address, instruction_as_word, 0u32) is added.
        Self::constrain_add_initial_digest(eval, trace_eval, lookup_elements);

        // subtract final digest
        // For each used Pc, one tuple (address, instruction_as_word, final_counter) is subtracted.
        Self::constrain_subtract_final_digest(eval, trace_eval, lookup_elements);

        // subtract program memory access, previous counter reads
        // For each access, one tuple (address, instruction_as_word, previous_couter) is subtracted.
        Self::constrain_subtract_access(eval, trace_eval, lookup_elements);

        // add program memory access, new counter write backs
        // For each access, one tuple (address, instruction_as_word, new_counter) is added.
        Self::constrain_add_access(eval, trace_eval, lookup_elements);
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
        original_traces: &FinalizedTraces,
        program_traces: &ProgramTraces,
        lookup_element: &ProgramCheckLookupElements,
    ) {
        let [prg_memory_flag] = program_traces.get_base_column(ProgramColumn::PrgMemoryFlag);
        let prg_memory_pc = program_traces.get_base_column::<WORD_SIZE>(ProgramColumn::PrgMemoryPc);
        let prg_memory_word =
            program_traces.get_base_column::<WORD_SIZE>(ProgramColumn::PrgMemoryWord);
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
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &ProgramCheckLookupElements,
    ) {
        let [prg_memory_flag] = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryFlag);
        let prg_memory_pc = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryPc);
        let prg_memory_word = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryWord);
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

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &tuple,
        ));
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
        original_traces: &FinalizedTraces,
        program_traces: &ProgramTraces,
        lookup_element: &ProgramCheckLookupElements,
    ) {
        let [prg_memory_flag] = program_traces.get_base_column(ProgramColumn::PrgMemoryFlag);
        let prg_memory_pc = program_traces.get_base_column::<WORD_SIZE>(ProgramColumn::PrgMemoryPc);
        let prg_memory_word =
            program_traces.get_base_column::<WORD_SIZE>(ProgramColumn::PrgMemoryWord);
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
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &ProgramCheckLookupElements,
    ) {
        let [prg_memory_flag] = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryFlag);
        let prg_memory_pc = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryPc);
        let prg_memory_word = program_trace_eval!(trace_eval, ProgramColumn::PrgMemoryWord);
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
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-numerator).into(),
            &tuple,
        ));
    }

    /// On each program memory access:
    /// * 1 / lookup_element.combine(tuple_old) is subtracted
    /// where tuples contain (the address, the whole word of the instruction, previous counter value).
    ///
    /// The numerator is zero on the padding rows, so that the row doesn't contribute to the logup sum.
    fn subtract_access(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        lookup_element: &ProgramCheckLookupElements,
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
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &ProgramCheckLookupElements,
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

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-numerator).into(),
            &tuple,
        ));
    }

    /// On each program memory access:
    /// * 1 / lookup_element.combine(tuple_new) is added
    /// where tuples contain (the address, the whole word of the instruction, current counter value).
    /// The counter value is incremented by one on each access.
    ///
    /// The numerator is zero when the row is padding, so that the row doesn't contribute to the logup sum.
    fn add_access(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        lookup_element: &ProgramCheckLookupElements,
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
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &ProgramCheckLookupElements,
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
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &tuple,
        ));
    }
}
#[cfg(test)]
mod test {

    use crate::{
        chips::{AddChip, CpuChip},
        test_utils::assert_chip,
        trace::{program_trace::ProgramTracesBuilder, utils::IntoBaseFields},
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_prog_mem_check_add_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_trace =
            ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, view.get_program_memory());
        let mut side_note = SideNote::new(&program_trace, &view);

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
                [0u8; WORD_SIZE_HALVED].into_base_fields()
            );
        }
        for item in side_note.program_mem_check.last_access_counter.iter() {
            assert_eq!(*item.1, 1, "unexpected number of accesses to Pc");
        }
        assert_chip::<ProgramMemCheckChip>(traces, Some(program_trace.finalize()));
    }
}
