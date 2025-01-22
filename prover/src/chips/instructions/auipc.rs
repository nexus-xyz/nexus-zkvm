use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTracesBuilder,
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

use super::add;

pub struct ExecutionResult {
    pub value_a: Word,
    pub carry_bits: BoolWord,
}

pub struct AuipcChip;

impl ExecuteChip for AuipcChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let pc = program_step.step.pc.to_le_bytes();
        let imm = (program_step.step.instruction.op_c << 12).to_le_bytes();

        // value_a = pc + (imm << 12)
        let (value_a, carry_bits) = add::add_with_carries(pc, imm);

        ExecutionResult {
            value_a,
            carry_bits,
        }
    }
}

impl MachineChip for AuipcChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &ProgramTracesBuilder,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::AUIPC)
        ) {
            return;
        }

        let ExecutionResult {
            value_a,
            carry_bits,
        } = Self::execute(vm_step);

        // Fill valueA and its carry flag.
        // ValueC is filled in CPUChip.
        traces.fill_columns(row_idx, value_a, Column::ValueA);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let modulus = E::F::from(256u32.into());
        let value_a = trace_eval!(trace_eval, ValueA);
        let carry_bits = trace_eval!(trace_eval, CarryFlag);
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Pc);
        let [is_auipc] = trace_eval!(trace_eval, Column::IsAuipc);

        // Setting a_val = pc + c_val
        // is_auipc・(pc_1 + c_val_1 - carry_1·2^8 - a_val_1) = 0
        // is_auipc・(pc_2 + c_val_2 + carry_1 - carry_2·2^8 - a_val_2) = 0
        // is_auipc・(pc_3 + c_val_3 + carry_2 - carry_3·2^8 - a_val_3) = 0
        // is_auipc・(pc_4 + c_val_4 + carry_3 - carry_4·2^8 - a_val_4) = 0
        eval.add_constraint(
            is_auipc.clone()
                * (pc[0].clone() + value_c[0].clone()
                    - carry_bits[0].clone() * modulus.clone()
                    - value_a[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_auipc.clone()
                    * (pc[i].clone() + value_c[i].clone() + carry_bits[i - 1].clone()
                        - carry_bits[i].clone() * modulus.clone()
                        - value_a[i].clone()),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{CpuChip, ProgramMemCheckChip, RegisterMemCheckChip, TypeUChip},
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::{Emulator, HarvardEmulator},
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Case 1: AUIPC with a small positive value
            // AUIPC x1, 0x1 (x1 = PC + 0x1000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 1, 0, 0x1),
            // Case 2: AUIPC with a large positive value
            // AUIPC x2, 0xFFFFF (x2 = PC + 0xFFFFF000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 2, 0, 0xFFFFF),
            // Case 3: AUIPC with zero
            // AUIPC x3, 0x0 (x3 = PC + 0x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 3, 0, 0x0),
            // Case 4: AUIPC with a value that sets some interesting bit patterns
            // AUIPC x4, 0xABCDE (x4 = PC + 0xABCDE000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 4, 0, 0xABCDE),
            // Case 5: AUIPC with x0 as destination (should not change x0)
            // AUIPC x0, 0x12345 (Should not change x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 0, 0, 0x12345),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_auipc_instructions() {
        type Chips = (
            CpuChip,
            TypeUChip,
            AuipcChip,
            ProgramMemCheckChip,
            RegisterMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let emulator = HarvardEmulator::from_basic_blocks(&basic_block);
        let program_memory = emulator.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::new(LOG_SIZE, program_memory);
        let mut side_note = SideNote::new(&program_traces, &emulator);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &program_traces,
                &mut side_note,
            );
        }
        assert_chip::<Chips>(traces, None, Some(program_traces.finalize()));
    }
}
