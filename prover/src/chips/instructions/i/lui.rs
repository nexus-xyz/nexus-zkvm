use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

pub struct ExecutionResult {
    pub value_a: Word,
}

impl ExecuteChip for LuiChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let imm = (program_step.step.instruction.op_c << 12).to_le_bytes();

        // value_a = (imm << 12)
        let value_a = imm;

        ExecutionResult { value_a }
    }
}

pub struct LuiChip;
impl MachineChip for LuiChip {
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
            Some(BuiltinOpcode::LUI)
        ) {
            return;
        }

        let ExecutionResult { value_a } = Self::execute(vm_step);

        traces.fill_columns(row_idx, value_a, Column::ValueA);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_c = trace_eval!(trace_eval, ValueC);
        let [is_lui] = trace_eval!(trace_eval, Column::IsLui);

        // Setting a_val = c_val
        // is_lui・(c_val_1 - a_val_1) = 0
        // is_lui・(c_val_2 - a_val_2) = 0
        // is_lui・(c_val_3 - a_val_3) = 0
        // is_lui・(c_val_4 - a_val_4) = 0
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_lui.clone() * (value_c[i].clone() - value_a[i].clone()));
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{CpuChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps,
            program_trace::{self},
            PreprocessedTraces,
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
            // Case 1: LUI with a small positive value
            // LUI x1, 0x1 (Load 0x1000 into x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 1, 0, 0x1),
            // Case 2: LUI with a large positive value
            // LUI x2, 0xFFFFF (Load 0xFFFFF000 into x2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 2, 0, 0xFFFFF),
            // Case 3: LUI with zero
            // LUI x3, 0x0 (Load 0x0 into x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 3, 0, 0x0),
            // Case 4: LUI with a value that sets some lower bits
            // LUI x4, 0xABCDE (Load 0xABCDE000 into x4)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 4, 0, 0xABCDE),
            // Case 5: LUI with x0 as destination (should not change x0)
            // LUI x0, 0x12345 (Should not change x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 0, 0, 0x12345),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_lui_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            LuiChip,
            ProgramMemCheckChip,
            RegisterMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces =
            program_trace::ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

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
