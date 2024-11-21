use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::machine2::{
    column::Column::*,
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::TraceEval, ProgramStep, Traces, Word},
    traits::{ExecuteChip, MachineChip},
};

// Support AND and ANDI opcodes.
pub struct AndChip;

pub struct ExecutionResult {
    and_bytes: Word,
    /// true when destination register is writable (not X0)
    value_a_effective_flag: bool,
}

impl ExecuteChip for AndChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let value_a_effective_flag = program_step.value_a_effectitve_flag();

        // Step 1. Break the computation to 8-bit limbs
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut value_a = Word::default();

        // Step 2. Compute the output.
        for i in 0..WORD_SIZE {
            value_a[i] = value_b[i] & value_c[i];
        }

        ExecutionResult {
            and_bytes: value_a,
            value_a_effective_flag,
        }
    }
}

impl MachineChip for AndChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if vm_step.step.is_padding {
            return;
        }
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::AND) | Some(BuiltinOpcode::ANDI)
        ) {
            return;
        }

        let ExecutionResult {
            and_bytes,
            value_a_effective_flag,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        debug_assert_eq!(
            and_bytes,
            vm_step
                .get_result()
                .expect("AND/ANDI instruction must have a result")
        );

        traces.fill_columns(row_idx, &and_bytes, ValueA);
        traces.fill_effective_columns(row_idx, &and_bytes, ValueAEffective, value_a_effective_flag);
    }

    fn add_constraints<E: EvalAtRow>(
        _eval: &mut E,
        _trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        // TODO: constrain output with a lookup.
    }
}

#[cfg(test)]
mod test {
    use crate::machine2::{
        chips::{AddChip, CpuChip},
        trace::trace_column,
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = Traces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        #[rustfmt::skip]
        let basic_block = BasicBlock::new(vec![
            // 0b11100 & 0b01010 = 0b01000
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 28, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 8, InstructionType::IType),
            // x3 = x1 & x2
            Instruction::new(Opcode::from(BuiltinOpcode::AND), 3, 1, 2, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_values() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        let mut traces = Traces::new(LOG_SIZE);

        for (row_idx, trace) in vm_traces.blocks.iter().enumerate() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // Fill in the main trace with the ValueB, valueC and Opcode
                CpuChip::fill_main_trace(&mut traces, row_idx, &program_step);
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step);
                AndChip::fill_main_trace(&mut traces, row_idx, &program_step);
            }
        }

        let vals = trace_column!(traces, 2, ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(vals);

        assert_eq!(output, 0b1000);

        // TODO: constraints tests
    }
}
