use num_traits::{Euclid, One};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self},
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

#[derive(Default)]
pub struct ExecutionResult {
    result: Word,
    shift_bits: [bool; 5],
    exp1_3: u8,
    h1: u8,
    rem: Word,
    rem_diff: Word,
    qt: Word,
}

pub struct SrlChip;

impl ExecuteChip for SrlChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let result = program_step.get_result().expect("SRL must have result");
        let value_b = program_step.get_value_b();
        // We know that imm is in range: 0 -> 31, thus we only get the 1st limb
        let value_c = program_step.get_value_c().0;
        let imm = value_c[0];

        let h1 = imm >> 5;
        let exp1_3 = 1 << (imm & 0b111);
        let mut sh = [false; 5];
        sh[0] = (imm & 1) == 1;
        sh[1] = ((imm >> 1) & 1) == 1;
        sh[2] = ((imm >> 2) & 1) == 1;
        sh[3] = ((imm >> 3) & 1) == 1;
        sh[4] = ((imm >> 4) & 1) == 1;

        let mut rem = [0u8; WORD_SIZE];
        let mut rem_diff = [0u8; WORD_SIZE];
        let mut qt = [0u8; WORD_SIZE];

        (qt[3], rem[3]) = value_b[3].div_rem_euclid(&exp1_3);
        for i in (0..WORD_SIZE - 1).rev() {
            let t = u16::from(value_b[i]) + (u16::from(rem[i + 1]) << 8);
            let (q, r) = t.div_rem_euclid(&(exp1_3 as u16));
            // It is guaranteed that q, r < 256
            rem[i] = r as u8;
            qt[i] = q as u8;
        }

        for i in 0..WORD_SIZE {
            rem_diff[i] = exp1_3 - 1 - rem[i];
        }

        Self::ExecutionResult {
            result,
            shift_bits: sh,
            exp1_3,
            h1,
            rem,
            rem_diff,
            qt,
        }
    }
}

impl MachineChip for SrlChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SRL) | Some(BuiltinOpcode::SRLI)
        ) {
            return;
        }

        let ExecutionResult {
            result,
            shift_bits,
            exp1_3,
            h1,
            rem,
            rem_diff,
            qt,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, result, Column::ValueA);
        traces.fill_columns(row_idx, rem, Column::Rem);
        traces.fill_columns(row_idx, rem_diff, Column::RemDiff);
        traces.fill_columns(row_idx, qt, Column::Qt);
        traces.fill_columns(row_idx, [h1, 0u8, 0u8, 0u8], Column::Helper1);
        traces.fill_columns(row_idx, shift_bits[0], Column::ShiftBit1);
        traces.fill_columns(row_idx, shift_bits[1], Column::ShiftBit2);
        traces.fill_columns(row_idx, shift_bits[2], Column::ShiftBit3);
        traces.fill_columns(row_idx, shift_bits[3], Column::ShiftBit4);
        traces.fill_columns(row_idx, shift_bits[4], Column::ShiftBit5);
        traces.fill_columns(row_idx, exp1_3, Column::Exp1_3);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let modulus = E::F::from(256u32.into());
        let value_a = trace_eval!(trace_eval, Column::ValueA);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        let [sh1] = trace_eval!(trace_eval, Column::ShiftBit1);
        let [sh2] = trace_eval!(trace_eval, Column::ShiftBit2);
        let [sh3] = trace_eval!(trace_eval, Column::ShiftBit3);
        let [sh4] = trace_eval!(trace_eval, Column::ShiftBit4);
        let [sh5] = trace_eval!(trace_eval, Column::ShiftBit5);
        let [h1, _, _, _] = trace_eval!(trace_eval, Column::Helper1);
        let [exp1_3] = trace_eval!(trace_eval, Column::Exp1_3);
        let rem = trace_eval!(trace_eval, Column::Rem);
        let qt = trace_eval!(trace_eval, Column::Qt);
        let [is_srl] = trace_eval!(trace_eval, Column::IsSrl);

        // is_srl・(sh1 + sh2・2 + sh3・4 + sh4・8 + sh5・16 + h1・32 - c_val_1) = 0
        eval.add_constraint(
            is_srl.clone()
                * (sh1.clone()
                    + sh2.clone() * E::F::from(2u32.into())
                    + sh3.clone() * E::F::from(4u32.into())
                    + sh4.clone() * E::F::from(8u32.into())
                    + sh5.clone() * E::F::from(16u32.into())
                    + h1 * E::F::from(32u32.into())
                    - value_c[0].clone()),
        );

        // Computing exponent exp1_3 to perform temporary 3-bit right shift
        // is_srl・ ((sh1+1)・(3・sh2+1)・(15・sh3+1) - exp1_3) = 0
        eval.add_constraint(
            is_srl.clone()
                * ((sh1.clone() + E::F::one())
                    * (sh2.clone() * E::F::from(3u32.into()) + E::F::one())
                    * (sh3.clone() * E::F::from(15u32.into()) + E::F::one())
                    - exp1_3.clone()),
        );

        // Performing a temporary right shift using 3 lower bits of shift amount
        // is_srl・ (b_val_4 - rem4 - qt4・exp1_3) = 0
        // is_srl・ (b_val_3 + rem4・2^8 - rem3 - qt3・exp1_3) = 0
        // is_srl・ (b_val_2 + rem3・2^8 - rem2 - qt2・exp1_3) = 0
        // is_srl・ (b_val_1 + rem2・2^8 - rem1 - qt1・exp1_3) = 0
        eval.add_constraint(
            is_srl.clone() * (value_b[3].clone() - rem[3].clone() - qt[3].clone() * exp1_3.clone()),
        );
        for i in (0..WORD_SIZE - 1).rev() {
            eval.add_constraint(
                is_srl.clone()
                    * (value_b[i].clone() + rem[i + 1].clone() * modulus.clone()
                        - rem[i].clone()
                        - qt[i].clone() * exp1_3.clone()),
            );
        }

        // Computing final right shift using remaining bits of shift amount
        // is_srl・ (a_val_4 - qt4・(1-sh4)・(1-sh5)) = 0
        // is_srl・ (a_val_3 - qt3・(1-sh4)・(1-sh5)- qt4・(sh4)・(1-sh5)) = 0
        // is_srl・ (a_val_2 - qt2・(1-sh4)・(1-sh5)- qt3・(sh4)・(1-sh5) - qt4・(1-sh4)・(sh5)) = 0
        // is_srl・ (a_val_1 - qt1・(1-sh4)・(1-sh5)- qt2・(sh4)・(1-sh5) - qt3・(1-sh4)・(sh5) - qt4・(sh4)・(sh5)) = 0
        eval.add_constraint(
            is_srl.clone()
                * (value_a[3].clone()
                    - qt[3].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_srl.clone()
                * (value_a[2].clone()
                    - qt[2].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[3].clone() * sh4.clone() * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_srl.clone()
                * (value_a[1].clone()
                    - qt[1].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[2].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - qt[3].clone() * (E::F::one() - sh4.clone()) * sh5.clone()),
        );
        eval.add_constraint(
            is_srl.clone()
                * (value_a[0].clone()
                    - qt[0].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[1].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - qt[2].clone() * (E::F::one() - sh4.clone()) * sh5.clone()
                    - qt[3].clone() * sh4.clone() * sh5.clone()),
        );

        // Range checks for remainder values rem{1,2,3,4}
        // is_srl・(exp1_3 - 1 - rem1 - rem1_diff) = 0
        // is_srl・(exp1_3 - 1 - rem2 - rem2_diff) = 0
        // is_srl・(exp1_3 - 1 - rem3 - rem3_diff) = 0
        // is_srl・(exp1_3 - 1 - rem4 - rem4_diff) = 0
        let rem_diff = trace_eval!(trace_eval, Column::RemDiff);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_srl.clone()
                    * (exp1_3.clone() - E::F::one() - rem[i].clone() - rem_diff[i].clone()),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SllChip, SubChip,
        },
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
        },
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
            // Test individual bit of shiftbits for SRL/SRLI
            // Set x7 = 0xFFFFFFFF (all bits set)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 7, 0, 7),
            // x8 = x7 >> 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 1),
            // x8 = x7 >> 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 2),
            // x8 = x7 >> 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 4),
            // x8 = x7 >> 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 8),
            // x8 = x7 >> 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 16),
            // x9 = x8 >> 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 9, 8, 0),
            // x9 = x8 >> 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 9, 8, 0),
            // Testing shift right with arbitrary values
            // Set x1 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 20),
            // Set x2 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 2),
            // x3 = x1 >> x2 (20 >> 2 = 5)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRL), 3, 1, 2),
            // x4 = x1 >> 3 (20 >> 3 = 2) using SRLI
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 4, 1, 3),
            // Set x5 = -20 (testing negative numbers)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 5, 0, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 5),
            // x6 = x5 >> 1 (-20 >> 1 = 2147483638, due to logical shift)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 6, 5, 1),
            // Set x7 = 0x80000000 (most significant bit set)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 7, 7, 31),
            // x8 = x7 >> 31 (0x80000000 >> 31 = 1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRLI), 8, 7, 31),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_srl_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            SubChip,
            AddChip,
            SrlChip,
            SllChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
