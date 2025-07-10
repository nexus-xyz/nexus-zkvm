use nexus_vm::WORD_SIZE;
use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow, Relation, RelationEntry},
    core::{backend::simd::m31::LOG_N_LANES, fields::m31::BaseField},
};

use crate::{
    column::{
        Column::{
            self, Reg1Address, Reg1TsPrev, Reg1ValPrev, Reg2Address, Reg2TsPrev, Reg2ValPrev,
            Reg3Address, Reg3TsPrev, Reg3ValPrev, ValueA, ValueAEffective, ValueAEffectiveFlag,
            ValueB, ValueC,
        },
        PreprocessedColumn,
    },
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTraces,
        regs::AccessResult,
        sidenote::SideNote,
        utils::FromBaseFields,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, IsTypeR, OpBFlag, Reg3Accessed, VirtualColumn},
};

/// A Chip for register memory checking
///
/// RegisterMemCheckChip needs to be located after all chips that access registers.
pub struct RegisterMemCheckChip;

const LOOKUP_TUPLE_SIZE: usize = 1 + WORD_SIZE + WORD_SIZE;
impl RegisterMemCheckChip {
    const TUPLE_SIZE: usize = LOOKUP_TUPLE_SIZE;
}

stwo_prover::relation!(RegisterCheckLookupElements, LOOKUP_TUPLE_SIZE);

impl MachineChip for RegisterMemCheckChip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
        _config: &ExtensionsConfig,
    ) {
        all_elements.insert(RegisterCheckLookupElements::draw(channel));
    }

    /// Fills `Reg{1,2,3}ValPrev` and `Reg{1,2,3}TsPrev` columns
    ///
    /// Assumes other chips have written to `Reg{1,2,3}Accessed` `Reg{1,2,3}Address` `Reg{1,2,3}Value`
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        // Fill ValueAEffective
        // This cannot be done in CPUChip because ValueA isn't available there yet.
        traces.fill_effective_columns(row_idx, ValueA, ValueAEffective, ValueAEffectiveFlag);

        assert!(row_idx < (u32::MAX - 3) as usize / 3);
        let clk = row_idx as u32 + 1;
        let reg1_cur_ts = clk * 3 + 1;
        let reg2_cur_ts = clk * 3 + 2;
        let reg3_cur_ts = clk * 3 + 3;

        // Read inputs to the chip
        let reg1_accessed = virtual_column::OpBFlag::read_from_traces_builder(traces, row_idx);
        let reg2_accessed = virtual_column::IsTypeR::read_from_traces_builder(traces, row_idx);
        let reg3_accessed: [BaseField; 1] =
            virtual_column::Reg3Accessed::read_from_traces_builder(traces, row_idx);
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
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let lookup_elements: &RegisterCheckLookupElements = lookup_elements.as_ref();
        let [value_a_effective_flag] = trace_eval!(trace_eval, ValueAEffectiveFlag);

        // value_a_effective can be constrained uniquely with value_a_effective_flag and value_a
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_a_effective = trace_eval!(trace_eval, ValueAEffective);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                value_a_effective[i].clone() - value_a[i].clone() * value_a_effective_flag.clone(),
            );
        }

        // Subtract previous register info
        let [reg1_accessed] = virtual_column::OpBFlag::eval(trace_eval);
        Self::constrain_subtract_prev_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg1_accessed.clone(),
            Reg1Address,
            Reg1TsPrev,
            Reg1ValPrev,
        );
        let [reg2_accessed] = virtual_column::IsTypeR::eval(trace_eval);
        Self::constrain_subtract_prev_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg2_accessed.clone(),
            Reg2Address,
            Reg2TsPrev,
            Reg2ValPrev,
        );
        let [reg3_accessed] = virtual_column::Reg3Accessed::eval(trace_eval);
        Self::constrain_subtract_prev_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg3_accessed.clone(),
            Reg3Address,
            Reg3TsPrev,
            Reg3ValPrev,
        );

        // Add current register info
        Self::constrain_add_cur_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg1_accessed,
            Reg1Address,
            PreprocessedColumn::Reg1TsCur,
            ValueB,
        );
        Self::constrain_add_cur_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg2_accessed,
            Reg2Address,
            PreprocessedColumn::Reg2TsCur,
            ValueC,
        );
        Self::constrain_add_cur_reg(
            eval,
            trace_eval,
            lookup_elements,
            reg3_accessed,
            Reg3Address,
            PreprocessedColumn::Reg3TsCur,
            ValueAEffective,
        );

        // Constrain ValueB and ValueC using Reg1ValPrev and Reg2ValPrev, when these registers are accessed
        // ValueB and ValueC are only used for reading from the registers, so they should not change the previous values.
        let reg1_val_prev = trace_eval!(trace_eval, Column::Reg1ValPrev);
        let reg2_val_prev = trace_eval!(trace_eval, Column::Reg2ValPrev);
        let [reg1_accessed] = virtual_column::OpBFlag::eval(trace_eval);
        let [reg2_accessed] = virtual_column::IsTypeR::eval(trace_eval);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);

        // is_alu = is_add + is_sub + is_slt + is_sltu + is_xor + is_or + is_and + is_sll + is_srl + is_sra +
        // is_mul + is_mulhu + is_divu + is_remu + is_div + is_rem + is_mulhsu + is_mulh
        let [is_alu] = virtual_column::IsAlu::eval(trace_eval);

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
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        _program_trace: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &RegisterCheckLookupElements = lookup_element.as_ref();
        // Written triples (reg_idx, cur_timestamp, cur_value) gets added.
        // Read triples (reg_idx, prev_timestamp, prev_value) gets subtracted.

        // Subtract previous register info
        Self::subtract_prev_reg::<OpBFlag>(
            logup_trace_gen,
            original_traces,
            lookup_element,
            Reg1Address,
            Reg1TsPrev,
            Reg1ValPrev,
        );
        Self::subtract_prev_reg::<IsTypeR>(
            logup_trace_gen,
            original_traces,
            lookup_element,
            Reg2Address,
            Reg2TsPrev,
            Reg2ValPrev,
        );
        Self::subtract_prev_reg::<Reg3Accessed>(
            logup_trace_gen,
            original_traces,
            lookup_element,
            Reg3Address,
            Reg3TsPrev,
            Reg3ValPrev,
        );

        // Add current register info
        Self::add_cur_reg::<OpBFlag>(
            logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg1Address,
            PreprocessedColumn::Reg1TsCur,
            ValueB,
        );
        Self::add_cur_reg::<IsTypeR>(
            logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg2Address,
            PreprocessedColumn::Reg2TsCur,
            ValueC,
        );
        Self::add_cur_reg::<Reg3Accessed>(
            logup_trace_gen,
            original_traces,
            preprocessed_trace,
            lookup_element,
            Reg3Address,
            PreprocessedColumn::Reg3TsCur,
            ValueAEffective,
        );
    }
}

impl RegisterMemCheckChip {
    fn subtract_prev_reg<AccessFlag: VirtualColumn<1>>(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        lookup_element: &RegisterCheckLookupElements,
        reg_address: Column,
        prev_ts: Column,
        prev_value: Column,
    ) {
        let mut logup_col_gen = logup_trace_gen.new_col();
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
            let numerator = -(AccessFlag::read_from_finalized_traces(original_traces, vec_row)[0]);
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_subtract_prev_reg<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &RegisterCheckLookupElements,
        reg_accessed: E::F,
        reg_address: Column,
        prev_ts: Column,
        prev_value: Column,
    ) {
        let [reg_idx] = trace_eval.column_eval(reg_address);
        let reg_prev_ts = trace_eval.column_eval::<WORD_SIZE>(prev_ts);
        let reg_prev_value = trace_eval.column_eval::<WORD_SIZE>(prev_value);
        let mut tuple = vec![reg_idx];
        for elm in reg_prev_ts.into_iter().chain(reg_prev_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);

        let numerator = -reg_accessed;
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &tuple,
        ));
    }

    fn add_cur_reg<AccessFlag: VirtualColumn<1>>(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        lookup_element: &RegisterCheckLookupElements,
        reg_address: Column,
        cur_ts: PreprocessedColumn,
        cur_value: Column,
    ) {
        let mut logup_col_gen = logup_trace_gen.new_col();
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
            let [numerator] = AccessFlag::read_from_finalized_traces(original_traces, vec_row);
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_add_cur_reg<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &RegisterCheckLookupElements,
        reg_accessed: E::F,
        reg_address: Column,
        cur_ts: PreprocessedColumn,
        cur_value: Column,
    ) {
        let [reg_idx] = trace_eval.column_eval(reg_address);
        let reg_cur_ts = trace_eval.preprocessed_column_eval::<WORD_SIZE>(cur_ts);
        let reg_cur_value = trace_eval.column_eval::<WORD_SIZE>(cur_value);
        let mut tuple = vec![reg_idx];
        for elm in reg_cur_ts.into_iter().chain(reg_cur_value.into_iter()) {
            tuple.push(elm);
        }
        assert_eq!(tuple.len(), Self::TUPLE_SIZE);

        let numerator = reg_accessed;
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &tuple,
        ));
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
    assert!(
        reg_idx != 0 || cur_value == 0,
        "writing non-zero to X0, reg_idx: {}, cur_value: {}, row_idx: {}",
        reg_idx,
        cur_value,
        row_idx
    );
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
    use super::RegisterMemCheckChip;
    use nexus_vm::{
        emulator::ProgramInfo,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;
    use stwo_prover::core::fields::qm31::SecureField;

    use crate::{
        chips::{AddChip, CpuChip},
        extensions::{final_reg::FinalRegEval, ExtensionComponent, ExtensionsConfig},
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps,
            program_trace::{ProgramTraceRef, ProgramTracesBuilder},
            PreprocessedTraces, TracesBuilder,
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
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_info = ProgramInfo::dummy();
        let program_trace_ref = ProgramTraceRef {
            program_memory: &program_info,
            init_memory: Default::default(),
            exit_code: Default::default(),
            public_output: Default::default(),
        };
        let program_traces = ProgramTracesBuilder::new(LOG_SIZE, program_trace_ref);
        let mut side_note = super::SideNote::new(&program_traces, &view);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            CpuChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );

            // Now fill in the traces with ValueA and CarryFlags
            AddChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
            RegisterMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &Default::default(),
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        let (lookup_elements, claimed_sum_1) = assert_chip::<RegisterMemCheckChip>(traces, None);

        // verify that logup sums match
        let ext = ExtensionComponent::final_reg();
        let component_trace =
            ext.generate_component_trace(FinalRegEval::LOG_SIZE, program_trace_ref, &mut side_note);
        let (_, claimed_sum_2) =
            ext.generate_interaction_trace(component_trace, &side_note, &lookup_elements);
        assert_eq!(claimed_sum_1 + claimed_sum_2, SecureField::zero());
    }
}
