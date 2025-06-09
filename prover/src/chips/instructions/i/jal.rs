use stwo_prover::{constraint_framework::EvalAtRow, core::fields::FieldExpOps};

use nexus_vm::riscv::BuiltinOpcode;

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

use super::add;

pub struct ExecutionResult {
    pub pc_next: Word,
    pub pc_carry_bits: [bool; 2], // At 16-bit boundaries
    pub value_a: Word,
    pub carry_bits: [bool; 2], // At 16-bit boundaries
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

        let pc_carry_bits = [pc_carry_bits[1], pc_carry_bits[3]];
        let carry_bits = [carry_bits[1], carry_bits[3]];

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
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
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
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
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
        // carry1_{2,4} used for carry handling
        // is_jal・(4 + pc_1 + pc_2 * 256 - carry1_1·2^{16} - a_val_1 - a_val_2 * 256) = 0
        eval.add_constraint(
            is_jal.clone()
                * (E::F::from(4.into()) + pc[0].clone() + pc[1].clone() * modulus.clone()
                    - carry_bits[0].clone() * modulus.clone().pow(2)
                    - value_a[0].clone()
                    - value_a[1].clone() * modulus.clone()),
        );
        // is_jal・(pc_3 + pc_4 * 256 + carry1_1 - carry1_2·2^{16} - a_val_3 - a_val_4 * 256) = 0
        eval.add_constraint(
            is_jal.clone()
                * (pc[2].clone() + pc[3].clone() * modulus.clone() + carry_bits[0].clone()
                    - carry_bits[1].clone() * modulus.clone().pow(2)
                    - value_a[2].clone()
                    - value_a[3].clone() * modulus.clone()),
        );

        // Setting pc_next based on comparison result
        // pc_next=pc+c_val
        // pc_carry_{2,4} used for carry handling
        // is_jal・(c_val_1 + c_val_2 * 256 + pc_1 + pc_2 * 256 - pc_carry_1·2^{16} - pc_next_1 - pc_next_2 * 256) = 0
        eval.add_constraint(
            is_jal.clone()
                * (value_c[0].clone()
                    + value_c[1].clone() * modulus.clone()
                    + pc[0].clone()
                    + pc[1].clone() * modulus.clone()
                    - pc_carry_bits[0].clone() * modulus.clone().pow(2)
                    - pc_next[0].clone()
                    - pc_next[1].clone() * modulus.clone()),
        );
        // is_jal・(c_val_3 + c_val_4 * 256 + pc_3 + pc_4 * 256 + pc_carry_1 - pc_carry_2·2^{16} - pc_next_3 - pc_next_4 * 256) = 0
        eval.add_constraint(
            is_jal.clone()
                * (value_c[2].clone()
                    + value_c[3].clone() * modulus.clone()
                    + pc[2].clone()
                    + pc[3].clone() * modulus.clone()
                    + pc_carry_bits[0].clone()
                    - pc_carry_bits[1].clone() * modulus.clone().pow(2)
                    - pc_next[2].clone()
                    - pc_next[3].clone() * modulus.clone()),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip},
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
            DecodingCheckChip,
            AddChip,
            JalChip,
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
