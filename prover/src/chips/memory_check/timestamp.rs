use std::array;

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::WORD_SIZE;

use crate::{
    chips::subtract_with_borrow,
    column::{
        Column::{
            self, CH1Minus, CH2Minus, CH3Minus, CReg1TsPrev, CReg2TsPrev, CReg3TsPrev, Reg1TsPrev,
            Reg2TsPrev, Reg3TsPrev,
        },
        PreprocessedColumn,
    },
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        utils::FromBaseFields,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::MachineChip,
};

/// This chip adds constraints that the previous timestamp is smaller than the current timestamp
/// This Chip needs to fill the main trace after RegisterMemCheckChip
pub struct TimestampChip;

impl MachineChip for TimestampChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let clk: u32 = row_idx as u32 + 1;
        let reg1_ts_cur = clk * 3 + 1;
        let reg2_ts_cur = clk * 3 + 2;
        let reg3_ts_cur = clk * 3 + 3;

        let reg1_ts_prev: [_; WORD_SIZE] = traces.column(row_idx, Reg1TsPrev);
        let reg2_ts_prev: [_; WORD_SIZE] = traces.column(row_idx, Reg2TsPrev);
        let reg3_ts_prev: [_; WORD_SIZE] = traces.column(row_idx, Reg3TsPrev);

        let reg1_ts_prev = u32::from_base_fields(reg1_ts_prev);
        let reg2_ts_prev = u32::from_base_fields(reg2_ts_prev);
        let reg3_ts_prev = u32::from_base_fields(reg3_ts_prev);

        assert!(reg1_ts_prev < reg1_ts_cur);
        assert!(reg2_ts_prev < reg2_ts_cur);
        assert!(reg3_ts_prev < reg3_ts_cur);

        let (c_reg1_ts_prev, ch1_minus) =
            decr_subtract_with_borrow(reg1_ts_cur.to_le_bytes(), (reg1_ts_prev).to_le_bytes());
        let (c_reg2_ts_prev, ch2_minus) =
            decr_subtract_with_borrow(reg2_ts_cur.to_le_bytes(), (reg2_ts_prev).to_le_bytes());
        let (c_reg3_ts_prev, ch3_minus) =
            decr_subtract_with_borrow(reg3_ts_cur.to_le_bytes(), (reg3_ts_prev).to_le_bytes());
        traces.fill_columns(row_idx, c_reg1_ts_prev, CReg1TsPrev);
        traces.fill_columns(row_idx, c_reg2_ts_prev, CReg2TsPrev);
        traces.fill_columns(row_idx, c_reg3_ts_prev, CReg3TsPrev);
        traces.fill_columns(row_idx, [ch1_minus[1], ch1_minus[3]], CH1Minus);
        traces.fill_columns(row_idx, [ch2_minus[1], ch2_minus[3]], CH2Minus);
        traces.fill_columns(row_idx, [ch3_minus[1], ch3_minus[3]], CH3Minus);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let ch1_minus = trace_eval!(trace_eval, CH1Minus);
        let ch2_minus = trace_eval!(trace_eval, CH2Minus);
        let ch3_minus = trace_eval!(trace_eval, CH3Minus);

        // Range of CH{1,2,3}Minus are constrained in RangeBoolChip.

        // The most significant borrow should be zero; this enforces the desired inequality.
        eval.add_constraint(ch1_minus[WORD_SIZE_HALVED - 1].clone());
        eval.add_constraint(ch2_minus[WORD_SIZE_HALVED - 1].clone());
        eval.add_constraint(ch3_minus[WORD_SIZE_HALVED - 1].clone());

        let reg1_ts_prev = trace_eval!(trace_eval, Reg1TsPrev);
        let reg2_ts_prev = trace_eval!(trace_eval, Reg2TsPrev);
        let reg3_ts_prev = trace_eval!(trace_eval, Reg3TsPrev);
        let reg1_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg1TsCur);
        let reg2_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg2TsCur);
        let reg3_ts_cur = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Reg3TsCur);
        let c_reg1_ts_prev = trace_eval!(trace_eval, CReg1TsPrev);
        let c_reg2_ts_prev = trace_eval!(trace_eval, CReg2TsPrev);
        let c_reg3_ts_prev = trace_eval!(trace_eval, CReg3TsPrev);

        constrain_diff_minus_one(eval, ch1_minus, c_reg1_ts_prev, reg1_ts_cur, reg1_ts_prev);
        constrain_diff_minus_one(eval, ch2_minus, c_reg2_ts_prev, reg2_ts_cur, reg2_ts_prev);
        constrain_diff_minus_one(eval, ch3_minus, c_reg3_ts_prev, reg3_ts_cur, reg3_ts_prev);
    }
}

/// Performs x - 1 - y, returning the result and the borrow bits
///
/// Note that for - 1 - y, for every limb, just one borrow bit suffices
pub fn decr_subtract_with_borrow(x: Word, y: Word) -> (Word, BoolWord) {
    let (diff, borrow1) = subtract_with_borrow(x, 1u32.to_le_bytes());
    let (diff, borrow2) = subtract_with_borrow(diff, y);
    for i in 0..WORD_SIZE {
        assert!(!borrow1[i] || !borrow2[i]);
    }
    let borrow = array::from_fn(|i| borrow1[i] | borrow2[i]);
    (diff, borrow)
}

fn constrain_diff_minus_one<E: EvalAtRow>(
    eval: &mut E,
    ch1_minus: [<E as EvalAtRow>::F; WORD_SIZE_HALVED],
    c_reg_ts_prev: [<E as EvalAtRow>::F; WORD_SIZE],
    reg_ts_cur: [<E as EvalAtRow>::F; WORD_SIZE],
    reg_ts_prev: [<E as EvalAtRow>::F; WORD_SIZE],
) {
    let modulus = E::F::from(256u32.into());
    // Constrain CH{1,2,3} and CReg{1,2,3}TsPrev using subtraction
    // (c_reg_ts_prev_1 + 256 * c_reg_ts_prev_2) + (reg_ts_prev_1 + 256 * reg_ts_prev_2) + 1 = (reg_ts_cur_1 + 256 * reg_ts_cur_2) + c_h1-_1・2^16
    eval.add_constraint(
        c_reg_ts_prev[0].clone()
            + c_reg_ts_prev[1].clone() * modulus.clone()
            + reg_ts_prev[0].clone()
            + reg_ts_prev[1].clone() * modulus.clone()
            + E::F::one()
            - (ch1_minus[0].clone() * E::F::from(BaseField::from(1 << 16))
                + reg_ts_cur[0].clone()
                + reg_ts_cur[1].clone() * modulus.clone()),
    );
    // (c_reg_ts_prev_3 + 256 * c_reg_ts_prev_4) + (reg_ts_prev_3 + 256 * reg_ts_prev_4) + c_h1-_1 = (reg_ts_cur_3 + 256 * reg_ts_cur_4) + c_h1-_2・2^16
    eval.add_constraint(
        c_reg_ts_prev[2].clone()
            + c_reg_ts_prev[3].clone() * modulus.clone()
            + reg_ts_prev[2].clone()
            + reg_ts_prev[3].clone() * modulus.clone()
            + ch1_minus[0].clone()
            - (ch1_minus[1].clone() * E::F::from(BaseField::from(1 << 16))
                + reg_ts_cur[2].clone()
                + reg_ts_cur[3].clone() * modulus.clone()),
    );
}

#[cfg(test)]
mod test {
    use super::TimestampChip;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    use crate::{
        chips::{AddChip, CpuChip, RegisterMemCheckChip},
        extensions::ExtensionsConfig,
        test_utils::assert_chip,
        trace::{
            program_trace::ProgramTracesBuilder, sidenote::SideNote, PreprocessedTraces,
            ProgramStep, TracesBuilder,
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
    fn test_timestamp_check_success() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &view);

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
            TimestampChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<TimestampChip>(traces, None);
    }
}
