use num_traits::One;
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
    qt: Word,
}

pub struct SllChip;

impl ExecuteChip for SllChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let result = program_step.get_result().expect("SLL must have result");
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
        let mut qt = [0u8; WORD_SIZE];

        let t = u16::from(value_b[0]) * u16::from(exp1_3);
        rem[0] = (t & 0xFF) as _;
        qt[0] = (t >> 8) as _;

        for i in 1..WORD_SIZE {
            let t = u16::from(value_b[i]) * u16::from(exp1_3) + qt[i - 1] as u16;
            rem[i] = (t & 0xFF) as _;
            qt[i] = (t >> 8) as _;
        }

        Self::ExecutionResult {
            result,
            shift_bits: sh,
            exp1_3,
            h1,
            rem,
            qt,
        }
    }
}

impl MachineChip for SllChip {
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
            Some(BuiltinOpcode::SLL) | Some(BuiltinOpcode::SLLI)
        ) {
            return;
        }

        let ExecutionResult {
            result,
            shift_bits,
            exp1_3,
            h1,
            rem,
            qt,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, result, Column::ValueA);
        traces.fill_columns(row_idx, rem, Column::Rem);
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
        let [is_sll] = trace_eval!(trace_eval, Column::IsSll);

        // is_sll・(sh1 + sh2・2 + sh3・4 + sh4・8 + sh5・16 + h1・32 - c_val_1) = 0
        eval.add_constraint(
            is_sll.clone()
                * (sh1.clone()
                    + sh2.clone() * E::F::from(2u32.into())
                    + sh3.clone() * E::F::from(4u32.into())
                    + sh4.clone() * E::F::from(8u32.into())
                    + sh5.clone() * E::F::from(16u32.into())
                    + h1 * E::F::from(32u32.into())
                    - value_c[0].clone()),
        );

        // Computing exponent exp1_3 to perform temporary 3-bit left shift
        // is_sll・ ((sh1+1)・(3・sh2+1)・(15・sh3+1) - exp1_3) = 0
        eval.add_constraint(
            is_sll.clone()
                * ((sh1.clone() + E::F::one())
                    * (sh2.clone() * E::F::from(3u32.into()) + E::F::one())
                    * (sh3.clone() * E::F::from(15u32.into()) + E::F::one())
                    - exp1_3.clone()),
        );

        // Performing a temporary left shift using 3 lower bits of shift amount
        // is_sll・ (rem1 + qt1・2^8 - b_val_1・exp1_3) = 0
        // is_sll・ (rem2 + qt2・2^8 - qt1 - b_val_2・exp1_3) = 0
        // is_sll・ (rem3 + qt3・2^8 - qt2 - b_val_3・exp1_3) = 0
        // is_sll・ (rem4 + qt4・2^8 - qt3 - b_val_4・exp1_3) = 0
        eval.add_constraint(
            is_sll.clone()
                * (rem[0].clone() + qt[0].clone() * modulus.clone()
                    - value_b[0].clone() * exp1_3.clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_sll.clone()
                    * (rem[i].clone() + qt[i].clone() * modulus.clone()
                        - qt[i - 1].clone()
                        - value_b[i].clone() * exp1_3.clone()),
            );
        }

        // Computing final left shift using remaining bits of shift amount
        // is_sll・ (a_val_1 - rem1・(1-sh4)・(1-sh5)) = 0
        // is_sll・ (a_val_2 - rem2・(1-sh4)・(1-sh5)- rem1・(sh4)・(1-sh5)) = 0
        // is_sll・ (a_val_3 - rem3・(1-sh4)・(1-sh5)- rem2・(sh4)・(1-sh5) - rem1・(1-sh4)・(sh5)) = 0
        // is_sll・ (a_val_4 - rem4・(1-sh4)・(1-sh5)- rem3・(sh4)・(1-sh5) - rem2・(1-sh4)・(sh5) - rem1・(sh4)・(sh5)) = 0
        eval.add_constraint(
            is_sll.clone()
                * (value_a[0].clone()
                    - rem[0].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_sll.clone()
                * (value_a[1].clone()
                    - rem[1].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - rem[0].clone() * sh4.clone() * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_sll.clone()
                * (value_a[2].clone()
                    - rem[2].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - rem[1].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - rem[0].clone() * (E::F::one() - sh4.clone()) * sh5.clone()),
        );
        eval.add_constraint(
            is_sll.clone()
                * (value_a[3].clone()
                    - rem[3].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - rem[2].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - rem[1].clone() * (E::F::one() - sh4.clone()) * sh5.clone()
                    - rem[0].clone() * sh4.clone() * sh5.clone()),
        );
    }
}

#[cfg(test)]
mod test {

    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SubChip,
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
            // Test individual bit of shiftbits
            // Set x7 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 1),
            // x8 = x7 << 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 1),
            // x8 = x7 << 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 2),
            // x8 = x7 << 4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 4),
            // x8 = x7 << 8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 8),
            // x8 = x7 << 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 16),
            // x9 = x8 << 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 9, 8, 0),
            // x9 = x8 << 0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLL), 9, 8, 0),
            // Testing shift left with arbitrary values
            // Set x1 = 5
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 5),
            // Set x2 = 2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 2),
            // x3 = x1 << x2 (5 << 2 = 20)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLL), 3, 1, 2),
            // x4 = x1 << 3 (5 << 3 = 40) using SLLI
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 4, 1, 3),
            // Set x5 = -5 (testing negative numbers)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 1),
            // x6 = x5 << 1 (-5 << 1 = -10)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 6, 5, 1),
            // Set x7 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 1),
            // x8 = x7 << 31 (1 << 31 = 2147483648, which is 2^31)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 8, 7, 31),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_sll_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            SubChip,
            AddChip,
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
