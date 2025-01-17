use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

use super::add;

pub struct ExecutionResult {
    pub pc_next: Word,
    pub pc_carry_bits: BoolWord,
    pub value_a: Word,
    pub carry_bits: BoolWord,
}

pub struct JalChip;

impl ExecuteChip for JalChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        // 1. Compute pc_next = pc + imm
        // 2. value_a = pc + 4
        let (pc_next, pc_carry_bits) = add::add_with_carries(pc, imm);
        let (value_a, carry_bits) = add::add_with_carries(pc, 4u32.to_le_bytes());

        ExecutionResult {
            pc_next,
            pc_carry_bits,
            value_a,
            carry_bits,
        }
    }
}

impl MachineChip for JalChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::JAL)
        ) {
            return;
        }

        let ExecutionResult {
            pc_next,
            pc_carry_bits,
            value_a,
            carry_bits,
        } = Self::execute(vm_step);

        // Fill PcNext and CarryFlag, since Pc and Immediate are filled to the main trace in CPU.
        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, pc_carry_bits, Column::BorrowFlag);

        // Fill valueA and its carry flag.
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
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_carry_bits = trace_eval!(trace_eval, Column::BorrowFlag);
        let carry_bits = trace_eval!(trace_eval, Column::CarryFlag);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let [is_jal] = trace_eval!(trace_eval, Column::IsJal);

        // a_val=pc+4
        // carry1_{1,2,3,4} used for carry handling
        // is_jal・(4 + pc_1 - carry1_1·2^8 - a_val_1) = 0
        // is_jal・(pc_2 + carry1_1 - carry1_2·2^8 - a_val_2) = 0
        // is_jal・(pc_3 + carry1_2 - carry1_3·2^8 - a_val_3) = 0
        // is_jal・(pc_4 + carry1_3 - carry1_4·2^8 - a_val_4) = 0

        eval.add_constraint(
            is_jal.clone()
                * (E::F::from(4.into()) + pc[0].clone()
                    - carry_bits[0].clone() * modulus.clone()
                    - value_a[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_jal.clone()
                    * (pc[i].clone() + carry_bits[i - 1].clone()
                        - carry_bits[i].clone() * modulus.clone()
                        - value_a[i].clone()),
            );
        }

        // Setting pc_next based on comparison result
        // pc_next=pc+c_val
        // pc_carry_{1,2,3,4} used for carry handling
        // is_jal・(c_val_1 + pc_1 - pc_carry_1·2^8 - pc_next_1) = 0
        // is_jal・(c_val_2 + pc_2 + pc_carry_1 - pc_carry_2·2^8 - pc_next_2) = 0
        // is_jal・(c_val_3 + pc_3 + pc_carry_2 - pc_carry_3·2^8 - pc_next_3) = 0
        // is_jal・(c_val_4 + pc_4 + pc_carry_3 - pc_carry_4·2^8 - pc_next_4) = 0
        eval.add_constraint(
            is_jal.clone()
                * (value_c[0].clone() + pc[0].clone()
                    - pc_carry_bits[0].clone() * modulus.clone()
                    - pc_next[0].clone()),
        );

        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_jal.clone()
                    * (value_c[i].clone() + pc[i].clone() + pc_carry_bits[i - 1].clone()
                        - pc_carry_bits[i].clone() * modulus.clone()
                        - pc_next[i].clone()),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, ProgramMemCheckChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps,
            program_trace::{self},
            PreprocessedTraces,
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
            // Case 1: JAL with positive offset
            // JAL x3, 12 (Jump forward 12 bytes (3 instructions) and store return address in x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 3, 0, 12),
            // Instructions to skip
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 2: JAL with x0 as destination (used for unconditional jumps without saving return address)
            // JAL x0, 8 (Jump forward 8 bytes (2 instructions) without saving return address)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JAL), 0, 0, 8),
            // Instruction to skip
            Instruction::unimpl(),
            Instruction::nop(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_jal_instructions() {
        type Chips = (
            CpuChip,
            AddChip,
            JalChip,
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
        let program_traces = program_trace::ProgramTraces::new(LOG_SIZE, program_memory);
        let mut side_note = SideNote::new(&program_traces, emulator.get_public_input());
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
        assert_chip::<Chips>(traces, None, Some(program_traces));
    }
}
