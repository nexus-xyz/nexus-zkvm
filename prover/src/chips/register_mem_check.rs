use nexus_common::riscv::register::NUM_REGISTERS;
use nexus_vm::WORD_SIZE;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{
        logup::{LogupAtRow, LogupTraceGenerator, LookupElements},
        EvalAtRow, INTERACTION_TRACE_IDX,
    },
    core::{
        backend::simd::{
            m31::{PackedM31, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    column::{
        Column::{
            self, FinalRegTs, FinalRegValue, Reg1Accessed, Reg1Address, Reg1TsPrev, Reg1ValPrev,
            Reg2Accessed, Reg2Address, Reg2TsPrev, Reg2ValPrev, Reg3Accessed, Reg3Address,
            Reg3TsPrev, Reg3ValPrev, ValueA, ValueAEffective, ValueAEffectiveFlag, ValueB, ValueC,
        },
        PreprocessedColumn,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::{ProgramTraces, ProgramTracesBuilder},
        regs::AccessResult,
        sidenote::SideNote,
        utils::FromBaseFields,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

/// A Chip for register memory checking
///
/// RegisterMemCheckChip needs to be located after all chips that access registers.

pub struct RegisterMemCheckChip;

impl RegisterMemCheckChip {
    const TUPLE_SIZE: usize = 1 + WORD_SIZE + WORD_SIZE;
}

impl MachineChip for RegisterMemCheckChip {
    /// Fills `Reg{1,2,3}ValPrev` and `Reg{1,2,3}TsPrev` columns
    ///
    /// Assumes other chips have written to `Reg{1,2,3}Accessed` `Reg{1,2,3}Address` `Reg{1,2,3}Value`
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _vm_step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
        side_note: &mut SideNote,
    ) {
        // Fill ValueAEffective
        // This cannot be done in CPUChip because ValueA isn't available there yet.
        traces.fill_effective_columns(row_idx, ValueA, ValueAEffective, ValueAEffectiveFlag);
        // TODO: consider looking up clk, reg{1,2,3}_cur_ts in the preprocessed trace
        assert!(row_idx < (u32::MAX - 3) as usize / 3);
        let clk = row_idx as u32 + 1;
        let reg1_cur_ts = clk * 3 + 1;
        let reg2_cur_ts = clk * 3 + 2;
        let reg3_cur_ts = clk * 3 + 3;

        // Read inputs to the chip
        let reg1_accessed: [BaseField; 1] = traces.column(row_idx, Reg1Accessed);
        let reg2_accessed: [BaseField; 1] = traces.column(row_idx, Reg2Accessed);
        let reg3_accessed: [BaseField; 1] = traces.column(row_idx, Reg3Accessed);
        let reg1_address: [BaseField; 1] = traces.column(row_idx, Reg1Address);
        let reg2_address: [BaseField; 1] = traces.column(row_idx, Reg2Address);
        let reg3_address: [BaseField; 1] = traces.column(row_idx, Reg3Address);
        let reg1_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueB);
        let reg2_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueC);
        let reg3_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueAEffective);

        if !reg1_accessed[0].is_zero() {
            fill_prev_values(
                reg1_address,
                reg1_value,
                side_note,
                reg1_cur_ts,
                Reg1TsPrev,
                Reg1ValPrev,
                traces,
                row_idx,
            );
        }
        if !reg2_accessed[0].is_zero() {
            fill_prev_values(
                reg2_address,
                reg2_value,
                side_note,
                reg2_cur_ts,
                Reg2TsPrev,
                Reg2ValPrev,
                traces,
                row_idx,
            );
        }
        if !reg3_accessed[0].is_zero() {
            fill_prev_values(
                reg3_address,
                reg3_value,
                side_note,
                reg3_cur_ts,
                Reg3TsPrev,
                Reg3ValPrev,
                traces,
                row_idx,
            );
        }
        // If we reached the end, write the final register information
        if row_idx == traces.num_rows() - 1 {
            for reg_idx in 0..NUM_REGISTERS {
                let final_val = side_note.register_mem_check.last_access_value[reg_idx];
                traces.fill_columns(reg_idx, final_val, Column::FinalRegValue);
                let final_ts = side_note.register_mem_check.last_access_timestamp[reg_idx];
                traces.fill_columns(reg_idx, final_ts, Column::FinalRegTs);
            }
        }
    }
    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [value_a_effective_flag] = trace_eval!(trace_eval, ValueAEffectiveFlag);

        // value_a_effective can be constrainted uniquely with value_a_effective_flag and value_a
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_a_effective = trace_eval!(trace_eval, ValueAEffective);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                value_a_effective[i].clone() - value_a[i].clone() * value_a_effective_flag.clone(),
            );
        }

        let [is_first_32] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst32);
        let final_reg_value = trace_eval!(trace_eval, Column::FinalRegValue);
        let final_reg_ts = trace_eval!(trace_eval, Column::FinalRegTs);
        // After the first 32 rows, FinalRegValue and FinalRegTs should be zero
        // Not strictly needed because final_reg{value,ts} are only considered on the first 32 rows
        for i in 0..WORD_SIZE {
            eval.add_constraint((E::F::one() - is_first_32.clone()) * final_reg_value[i].clone());
            eval.add_constraint((E::F::one() - is_first_32.clone()) * final_reg_ts[i].clone());
        }

        // Logup constraints
        let [is_first] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add initial register info during the first 32 rows
        Self::constrain_add_initial_reg(&mut logup, eval, trace_eval, lookup_elements);

        // Subtract previous register info
        Self::constrain_subtract_prev_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg1Accessed,
            Reg1Address,
            Reg1TsPrev,
            Reg1ValPrev,
        );
        Self::constrain_subtract_prev_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg2Accessed,
            Reg2Address,
            Reg2TsPrev,
            Reg2ValPrev,
        );
        Self::constrain_subtract_prev_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg3Accessed,
            Reg3Address,
            Reg3TsPrev,
            Reg3ValPrev,
        );

        // Add current register info
        Self::constrain_add_cur_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg1Accessed,
            Reg1Address,
            PreprocessedColumn::Reg1TsCur,
            ValueB,
        );
        Self::constrain_add_cur_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg2Accessed,
            Reg2Address,
            PreprocessedColumn::Reg2TsCur,
            ValueC,
        );
        Self::constrain_add_cur_reg(
            &mut logup,
            eval,
            trace_eval,
            lookup_elements,
            Reg3Accessed,
            Reg3Address,
            PreprocessedColumn::Reg3TsCur,
            ValueAEffective,
        );

        // Subtract final register info (stored on the first 32 rows)
        Self::constrain_subtract_final_reg(&mut logup, eval, trace_eval, lookup_elements);

        logup.finalize(eval);

        // TODO: constrain prev_ts < cur_ts

        // Constrain ValueB and ValueC using Reg1ValPrev and Reg2ValPrev, when these registers are accessed
        // ValueB and ValueC are only used for reading from the registers, so they should not change the previous values.
        let reg1_val_prev = trace_eval!(trace_eval, Column::Reg1ValPrev);
        let reg2_val_prev = trace_eval!(trace_eval, Column::Reg2ValPrev);
        let [reg1_accessed] = trace_eval!(trace_eval, Column::Reg1Accessed);
        let [reg2_accessed] = trace_eval!(trace_eval, Column::Reg2Accessed);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        let [is_add] = trace_eval!(trace_eval, Column::IsAdd);
        let [is_sub] = trace_eval!(trace_eval, Column::IsSub);
        let [is_and] = trace_eval!(trace_eval, Column::IsAnd);
        let [is_or] = trace_eval!(trace_eval, Column::IsOr);
        let [is_xor] = trace_eval!(trace_eval, Column::IsXor);
        let [is_slt] = trace_eval!(trace_eval, Column::IsSlt);
        let [is_sltu] = trace_eval!(trace_eval, Column::IsSltu);

        // is_alu = is_add + is_sub + is_slt + is_sltu + is_xor + is_or + is_and + is_sll + is_srl + is_sra
        let is_alu = is_add + is_sub + is_slt + is_sltu + is_xor + is_or + is_and;

        for i in 0..WORD_SIZE {
            eval.add_constraint(
                reg1_accessed.clone()
                    * is_alu.clone()
                    * (value_b[i].clone() - reg1_val_prev[i].clone()),
            );
            eval.add_constraint(
                reg2_accessed.clone()
                    * is_alu.clone()
                    * (value_c[i].clone() - reg2_val_prev[i].clone()),
            );
        }

        // TODO: add constraints so that branch and store operations do not change rs1 and rs2.
    }
    fn fill_interaction_trace(
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        _program_trace: &ProgramTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());
        // Written triples (reg_idx, cur_timestamp, cur_value) gets added.
        // Read triples (reg_idx, prev_timestamp, prev_value) gets subtracted.

        // Add initial register info during the first 32 rows
        Self::add_initial_reg(
            &mut logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
        );

        // Subtract previous register info
        Self::subtract_prev_reg(
            &mut logup_trace_gen,
            original_traces,
            lookup_element,
            Reg1Accessed,
            Reg1Address,
            Reg1TsPrev,
            Reg1ValPrev,
        );
        Self::subtract_prev_reg(
            &mut logup_trace_gen,
            original_traces,
            lookup_element,
            Reg2Accessed,
            Reg2Address,
            Reg2TsPrev,
            Reg2ValPrev,
        );
        Self::subtract_prev_reg(
            &mut logup_trace_gen,
            original_traces,
            lookup_element,
            Reg3Accessed,
            Reg3Address,
            Reg3TsPrev,
            Reg3ValPrev,
        );

        // Add current register info
        Self::add_cur_reg(
            &mut logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg1Accessed,
            Reg1Address,
            PreprocessedColumn::Reg1TsCur,
            ValueB,
        );
        Self::add_cur_reg(
            &mut logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg2Accessed,
            Reg2Address,
            PreprocessedColumn::Reg2TsCur,
            ValueC,
        );
        Self::add_cur_reg(
            &mut logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg3Accessed,
            Reg3Address,
            PreprocessedColumn::Reg3TsCur,
            ValueAEffective,
        );

        // Subtract final register info (stored on the first 32 rows)
        Self::subtract_final_reg(
            &mut logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
        );

        let (ret, total_sum) = logup_trace_gen.finalize_last();
        assert_eq!(total_sum, SecureField::zero());
        ret
    }
}

impl RegisterMemCheckChip {
    fn add_initial_reg(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first_32] =
            preprocessed_trace.get_preprocessed_base_column(PreprocessedColumn::IsFirst32);
        let [row_idx] = preprocessed_trace.get_preprocessed_base_column(PreprocessedColumn::RowIdx);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple: [PackedM31; Self::TUPLE_SIZE] =
                [BaseField::zero().into(); 1 + WORD_SIZE + WORD_SIZE]; // reg_idx, cur_timestamp, cur_value
            let row_idx = row_idx.data[vec_row];
            tuple[0] = row_idx; // Use row_idx as register index
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = is_first_32.data[vec_row]; // Only the first 32 rows contribute to the sum.
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }
    fn constrain_add_initial_reg<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first_32] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst32);
        let mut tuple: [E::F; Self::TUPLE_SIZE] = std::array::from_fn(|_| E::F::zero());
        let [row_idx] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIdx);
        tuple[0] = row_idx; // Using row_idx as register index
        let denom = lookup_elements.combine(tuple.as_slice());
        let numerator = is_first_32;
        logup.write_frac(eval, Fraction::new(numerator.into(), denom));
    }

    fn subtract_final_reg(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first_32] =
            preprocessed_trace.get_preprocessed_base_column(PreprocessedColumn::IsFirst32);
        let [row_idx] = preprocessed_trace.get_preprocessed_base_column(PreprocessedColumn::RowIdx);
        let final_reg_ts: [_; WORD_SIZE] = original_traces.get_base_column(FinalRegTs);
        let final_reg_value: [_; WORD_SIZE] = original_traces.get_base_column(FinalRegValue);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let row_idx = row_idx.data[vec_row];
            let mut tuple = vec![row_idx]; // Use row_idx as register index
            for col in final_reg_ts.iter().chain(final_reg_value.iter()) {
                tuple.push(col.data[vec_row]);
            }
            assert_eq!(tuple.len(), Self::TUPLE_SIZE);
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = is_first_32.data[vec_row]; // Only the first 32 rows contribute to the sum.
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
    }
    fn constrain_subtract_final_reg<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first_32] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst32);
        let [row_idx] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::RowIdx);
        let final_reg_ts = trace_eval!(trace_eval, Column::FinalRegTs);
        let final_reg_value = trace_eval!(trace_eval, Column::FinalRegValue);
        let mut tuple = vec![row_idx];
        for elm in final_reg_ts.into_iter().chain(final_reg_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);
        let denom = lookup_elements.combine(tuple.as_slice());
        let numerator = is_first_32;
        logup.write_frac(eval, Fraction::new((-numerator).into(), denom));
    }
    fn subtract_prev_reg(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
        accessed: Column,
        reg_address: Column,
        prev_ts: Column,
        prev_value: Column,
    ) {
        let mut logup_col_gen = logup_trace_gen.new_col();
        let [reg_accessed] = original_traces.get_base_column(accessed);
        let [reg_idx] = original_traces.get_base_column(reg_address);
        let reg_prev_ts: [_; WORD_SIZE] = original_traces.get_base_column(prev_ts);
        let reg_prev_value: [_; WORD_SIZE] = original_traces.get_base_column(prev_value);
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![reg_idx.data[vec_row]];
            for col in reg_prev_ts.iter().chain(reg_prev_value.iter()) {
                tuple.push(col.data[vec_row]);
            }
            assert_eq!(tuple.len(), Self::TUPLE_SIZE);
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = -reg_accessed.data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }
    fn constrain_subtract_prev_reg<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
        accessed: Column,
        reg_address: Column,
        prev_ts: Column,
        prev_value: Column,
    ) {
        let [reg_accessed] = trace_eval.column_eval(accessed);
        let [reg_idx] = trace_eval.column_eval(reg_address);
        let reg_prev_ts = trace_eval.column_eval::<WORD_SIZE>(prev_ts);
        let reg_prev_value = trace_eval.column_eval::<WORD_SIZE>(prev_value);
        let mut tuple = vec![reg_idx];
        for elm in reg_prev_ts.into_iter().chain(reg_prev_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);
        let denom = lookup_elements.combine(tuple.as_slice());
        let numerator = -reg_accessed;
        logup.write_frac(eval, Fraction::new(numerator.into(), denom));
    }

    fn add_cur_reg(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
        accessed: Column,
        reg_address: Column,
        cur_ts: PreprocessedColumn,
        cur_value: Column,
    ) {
        let mut logup_col_gen = logup_trace_gen.new_col();
        let [reg_accessed] = original_traces.get_base_column(accessed);
        let [reg_idx] = original_traces.get_base_column(reg_address);
        let reg_cur_ts: [_; WORD_SIZE] = preprocessed_trace.get_preprocessed_base_column(cur_ts);
        let reg_cur_value: [_; WORD_SIZE] = original_traces.get_base_column(cur_value);
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![reg_idx.data[vec_row]];
            for col in reg_cur_ts.iter().chain(reg_cur_value.iter()) {
                tuple.push(col.data[vec_row]);
            }
            assert_eq!(tuple.len(), Self::TUPLE_SIZE);
            let denom = lookup_element.combine(tuple.as_slice());
            let numerator = reg_accessed.data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }
    fn constrain_add_cur_reg<E: EvalAtRow>(
        logup: &mut LogupAtRow<E>,
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
        accessed: Column,
        reg_address: Column,
        cur_ts: PreprocessedColumn,
        cur_value: Column,
    ) {
        let [reg_accessed] = trace_eval.column_eval(accessed);
        let [reg_idx] = trace_eval.column_eval(reg_address);
        let reg_cur_ts = trace_eval.preprocessed_column_eval::<WORD_SIZE>(cur_ts);
        let reg_cur_value = trace_eval.column_eval::<WORD_SIZE>(cur_value);
        let mut tuple = vec![reg_idx];
        for elm in reg_cur_ts.into_iter().chain(reg_cur_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);
        let denom = lookup_elements.combine(tuple.as_slice());
        let numerator = reg_accessed;
        logup.write_frac(eval, Fraction::new(numerator.into(), denom));
    }
}

fn fill_prev_values(
    reg_address: [BaseField; 1],
    reg_value: [BaseField; WORD_SIZE],
    side_note: &mut SideNote,
    reg_cur_ts: u32,
    dst_ts: Column,
    dst_val: Column,
    traces: &mut TracesBuilder,
    row_idx: usize,
) {
    let reg_idx = reg_address[0].0;
    let cur_value = u32::from_base_fields(reg_value);
    let AccessResult {
        prev_timestamp,
        prev_value,
    } = side_note
        .register_mem_check
        .access(reg_idx, reg_cur_ts, cur_value);
    traces.fill_columns(row_idx, prev_timestamp, dst_ts);
    traces.fill_columns(row_idx, prev_value, dst_val);
}

#[cfg(test)]
mod test {
    use nexus_vm::{
        emulator::HarvardEmulator,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    use crate::{
        chips::{AddChip, CpuChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
            TracesBuilder,
        },
        traits::MachineChip,
    };

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
    fn test_register_mem_check_success() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = super::SideNote::new(&program_traces, &HarvardEmulator::default(), []);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            CpuChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut program_traces,
                &mut side_note,
            );

            // Now fill in the traces with ValueA and CarryFlags
            AddChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut program_traces,
                &mut side_note,
            );
            RegisterMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &Default::default(),
                &mut program_traces,
                &mut side_note,
            );
        }
        assert_chip::<RegisterMemCheckChip>(traces, None);
    }
}
