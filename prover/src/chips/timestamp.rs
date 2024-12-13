use nexus_vm::WORD_SIZE;
use num_traits::One;

use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use crate::{
    chips::sub::subtract_with_borrow,
    column::{
        Column::{
            self, CH1Minus, CH2Minus, CH3Minus, CReg1TsPrev, CReg2TsPrev, CReg3TsPrev, Reg1TsPrev,
            Reg2TsPrev, Reg3TsPrev,
        },
        PreprocessedColumn,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        utils::FromBaseFields,
        ProgramStep, Traces,
    },
    traits::MachineChip,
};

/// This chip adds constraints that the previous timestamp is smaller than the current timestamp

pub struct TimestampChip;

impl MachineChip for TimestampChip {
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        _step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        // TODO: fetch these values from the preprocessed trace
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
            subtract_with_borrow(reg1_ts_cur.to_le_bytes(), (reg1_ts_prev + 1).to_le_bytes());
        let (c_reg2_ts_prev, ch2_minus) =
            subtract_with_borrow(reg2_ts_cur.to_le_bytes(), (reg2_ts_prev + 1).to_le_bytes());
        let (c_reg3_ts_prev, ch3_minus) =
            subtract_with_borrow(reg3_ts_cur.to_le_bytes(), (reg3_ts_prev + 1).to_le_bytes());
        traces.fill_columns(row_idx, c_reg1_ts_prev, CReg1TsPrev);
        traces.fill_columns(row_idx, c_reg2_ts_prev, CReg2TsPrev);
        traces.fill_columns(row_idx, c_reg3_ts_prev, CReg3TsPrev);
        traces.fill_columns(row_idx, ch1_minus, CH1Minus);
        traces.fill_columns(row_idx, ch2_minus, CH2Minus);
        traces.fill_columns(row_idx, ch3_minus, CH3Minus);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let ch1_minus = trace_eval!(trace_eval, CH1Minus);
        let ch2_minus = trace_eval!(trace_eval, CH2Minus);
        let ch3_minus = trace_eval!(trace_eval, CH3Minus);

        // Range of CH{1,2,3}Minus are constrained in RangeBoolChip.

        // The most significant borrow should be zero; this enforces the desired inequality.
        eval.add_constraint(ch1_minus[WORD_SIZE - 1].clone());
        eval.add_constraint(ch2_minus[WORD_SIZE - 1].clone());
        eval.add_constraint(ch3_minus[WORD_SIZE - 1].clone());

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

fn constrain_diff_minus_one<E: EvalAtRow>(
    eval: &mut E,
    ch1_minus: [<E as EvalAtRow>::F; WORD_SIZE],
    c_reg_ts_prev: [<E as EvalAtRow>::F; WORD_SIZE],
    reg_ts_cur: [<E as EvalAtRow>::F; WORD_SIZE],
    reg_ts_prev: [<E as EvalAtRow>::F; WORD_SIZE],
) {
    let modulus = E::F::from(256u32.into());
    // Constrain CH{1,2,3} and CReg{1,2,3}TsPrev using subtraction
    // c_reg_ts_prev_1 + reg_ts_prev_1 + 1 = reg_ts_cur_1 + c_h1-_1・2^8
    eval.add_constraint(
        c_reg_ts_prev[0].clone() + reg_ts_prev[0].clone() + E::F::one()
            - (ch1_minus[0].clone() * modulus.clone() + reg_ts_cur[0].clone()),
    );
    // c_reg_ts_prev_2 + reg_ts_prev_2 + c_h1-_1 = reg_ts_cur_2 + c_h1-_2・2^8
    // c_reg_ts_prev_3 + reg_ts_prev_3 + c_h1-_2 = reg_ts_cur_2 + c_h1-_3・2^8
    // c_reg_ts_prev_4 + reg_ts_prev_4 + c_h1-_3 = reg_ts_cur_2 + c_h1-_4・2^8
    for i in 1..WORD_SIZE {
        let borrow = ch1_minus[i - 1].clone();
        eval.add_constraint(
            c_reg_ts_prev[i].clone() + reg_ts_prev[i].clone() + borrow
                - (ch1_minus[i].clone() * modulus.clone() + reg_ts_cur[i].clone()),
        );
    }
}

#[cfg(test)]
mod test {

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    use crate::{
        test_utils::assert_chip,
        {
            chips::{AddChip, CpuChip, RegisterMemCheckChip, TimestampChip},
            trace::{sidenote::SideNote, PreprocessedTraces, ProgramStep, Traces},
            traits::MachineChip,
        },
    };

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
    fn test_timestamp_check_success() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        const LOG_SIZE: u32 = 8;
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();

        let program_steps = vm_traces.blocks.into_iter().map(|block| {
            let regs = block.regs;
            debug_assert_eq!(block.steps.len(), 1);
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

            // Now fill in the traces with ValueA and CarryFlags
            AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
            RegisterMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &Default::default(),
                &mut side_note,
            );
            TimestampChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        let mut preprocessed_column = PreprocessedTraces::empty(LOG_SIZE);
        preprocessed_column.fill_is_first();
        preprocessed_column.fill_is_first32();
        //        preprocessed_column.fill_row_idx();
        preprocessed_column.fill_timestamps();
        assert_chip::<TimestampChip>(traces, Some(preprocessed_column));
    }
}
