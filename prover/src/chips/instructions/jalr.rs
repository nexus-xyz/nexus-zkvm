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
    pub pc_next: Word,
    pub pc_next_aux: Word,
    pub qt_aux: u8,
    pub rem_aux: bool,
    pub pc_carry_bits: BoolWord,
    pub value_a: Word,
    pub carry_bits: BoolWord,
}

pub struct JalrChip;

impl ExecuteChip for JalrChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        // 1. Compute pc_next_aux = value_b + imm
        // 2. pc_next = qt_aux * 2 = pc_next_aux & 0xFFFF_FFFE
        // 3. value_a = pc + 4
        let (pc_next_aux, pc_carry_bits) = add::add_with_carries(value_b, imm);
        let mut pc_next = pc_next_aux;

        // If last bit of pc_next_aux is 0, then rem_aux = 0
        // If last bit of pc_next_aux is 1, then rem_aux = 1
        // So pc_next = pc_next_aux - rem_aux
        // Pc_next is always even (last bit is 0)
        let rem_aux = pc_next[0] & 0x1 == 1;
        pc_next[0] -= rem_aux as u8;

        // To ensure 2*qt_aux = pc_next
        let qt_aux = pc_next[0] >> 1;

        let (value_a, carry_bits) = add::add_with_carries(pc, 4u32.to_le_bytes());

        ExecutionResult {
            pc_next,
            pc_next_aux,
            qt_aux,
            rem_aux,
            pc_carry_bits,
            value_a,
            carry_bits,
        }
    }
}

impl MachineChip for JalrChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::JALR)
        ) {
            return;
        }

        let ExecutionResult {
            pc_next,
            pc_next_aux,
            qt_aux,
            rem_aux,
            pc_carry_bits,
            value_a,
            carry_bits,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, qt_aux, Column::QtAux);

        // Fill RemAux and PcNext.
        traces.fill_columns(row_idx, rem_aux, Column::RemAux);
        traces.fill_columns(row_idx, pc_next, Column::PcNext);

        // Fill PcNextAux and CarryFlag, since Pc and Immediate are filled to the main trace in CPU.
        traces.fill_columns(row_idx, pc_next_aux, Column::PcNextAux);
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
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_carry_bits = trace_eval!(trace_eval, Column::BorrowFlag);
        let carry_bits = trace_eval!(trace_eval, Column::CarryFlag);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let [rem_aux] = trace_eval!(trace_eval, Column::RemAux);
        let pc_next_aux = trace_eval!(trace_eval, Column::PcNextAux);
        let [qt_aux] = trace_eval!(trace_eval, Column::QtAux);
        let [is_jalr] = trace_eval!(trace_eval, Column::IsJalr);

        // a_val=pc+4
        // carry1_{1,2,3,4} used for carry handling
        // is_jalr・(4 + pc_1 - carry1_1·2^8 - a_val_1) = 0
        // is_jalr・(pc_2 + carry1_1 - carry1_2·2^8 - a_val_2) = 0
        // is_jalr・(pc_3 + carry1_2 - carry1_3·2^8 - a_val_3) = 0
        // is_jalr・(pc_4 + carry1_3 - carry1_4·2^8 - a_val_4) = 0

        eval.add_constraint(
            is_jalr.clone()
                * (E::F::from(4.into()) + pc[0].clone()
                    - carry_bits[0].clone() * modulus.clone()
                    - value_a[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_jalr.clone()
                    * (pc[i].clone() + carry_bits[i - 1].clone()
                        - carry_bits[i].clone() * modulus.clone()
                        - value_a[i].clone()),
            );
        }

        // Setting pc_next
        // pc_next_aux = b_val + c_val
        // pc_carry_{1,2,3,4} used for carry handling
        // is_jalr・(c_val_1 + b_val_1 - pc_carry_1·2^8 - pc_next_aux_1) = 0
        // is_jalr・(c_val_2 + b_val_2 + pc_carry_1 - pc_carry_2·2^8 - pc_next_aux_2) = 0
        // is_jalr・(c_val_3 + b_val_3 + pc_carry_2 - pc_carry_3·2^8 - pc_next_aux_3) = 0
        // is_jalr・(c_val_4 + b_val_4 + pc_carry_3 - pc_carry_4·2^8 - pc_next_aux_4) = 0
        eval.add_constraint(
            is_jalr.clone()
                * (value_c[0].clone() + value_b[0].clone()
                    - pc_carry_bits[0].clone() * modulus.clone()
                    - pc_next_aux[0].clone()),
        );

        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_jalr.clone()
                    * (value_c[i].clone() + value_b[i].clone() + pc_carry_bits[i - 1].clone()
                        - pc_carry_bits[i].clone() * modulus.clone()
                        - pc_next_aux[i].clone()),
            );
        }

        // Setting pc_next
        // pc_next = pc_next_aux & 0xFFFFFFFE
        // rem_aux, qt_aux used for setting bit 0 of pc_next_aux_1 to 0
        // is_jalr・(pc_next_aux_1 - qt_aux·2 - rem_aux) = 0
        // is_jalr・(qt_aux·2 - pc_next_1) = 0
        // is_jalr・(pc_next_aux_2 - pc_next_2) = 0
        // is_jalr・(pc_next_aux_3 - pc_next_3) = 0
        // is_jalr・(pc_next_aux_4 - pc_next_4) = 0

        eval.add_constraint(
            is_jalr.clone()
                * (pc_next_aux[0].clone()
                    - qt_aux.clone() * E::F::from(2.into())
                    - rem_aux.clone()),
        );
        eval.add_constraint(
            is_jalr.clone() * (qt_aux.clone() * E::F::from(2.into()) - pc_next[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(is_jalr.clone() * (pc_next_aux[i].clone() - pc_next[i].clone()));
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, LuiChip, ProgramMemCheckChip, Range128Chip, RegisterMemCheckChip,
        },
        test_utils::assert_chip,
        trace::{program::iter_program_steps, PreprocessedTraces},
    };

    use super::*;
    use nexus_common::constants::ELF_TEXT_START;
    use nexus_vm::{
        emulator::{Emulator, HarvardEmulator},
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        // Make sure the 12 lowest bit of ELF_TEXT_START are zeros.
        assert_eq!(ELF_TEXT_START & 0xFFF, 0);
        let basic_block = BasicBlock::new(vec![
            // Initialize registers
            // Set x1 = ELF_TEXT_START + 16 (base address for first JALR)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 1, 0, ELF_TEXT_START >> 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 1, 16),
            // Set x2 = ELF_TEXT_START + 44 (base address for second JALR)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 2, 0, ELF_TEXT_START >> 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 2, 44),
            // Case 1: JALR with positive offset
            // JALR x3, x1, 4 (Jump to x1 + 4 and store return address in x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 3, 1, 12),
            // Instructions to skip
            Instruction::unimpl(),
            // Target of first JALR
            // ADDI x4, x0, 1 (Set x4 = 1 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1),
            // Case 2: JALR with negative offset
            // JALR x5, x2, -8 (Jump to x2 - 8 and store return address in x5)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 5, 2, 0xFF8), // -8 in 12-bit two's complement
            // Instructions to skip
            Instruction::unimpl(),
            // Target of second JALR
            // ADDI x6, x0, 2 (Set x6 = 2 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 0, 2),
            // Case 3: JALR with x0 as destination (used for unconditional jumps without saving return address)
            // JALR x0, x1, 24 (Jump to x1 + 24 without saving return address)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 0, 1, 32),
            // Instruction to skip
            Instruction::unimpl(),
            // Target of last JALR
            // ADDI x7, x0, 3 (Set x7 = 3 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 3),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_jalr_instructions() {
        type Chips = (
            CpuChip,
            AddChip,
            LuiChip,
            JalrChip,
            Range128Chip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let emulator = HarvardEmulator::from_basic_blocks(&basic_block);
        let program_memory = emulator.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut program_traces = ProgramTracesBuilder::new(LOG_SIZE, program_memory);
        let mut side_note = SideNote::new(&program_traces, &emulator);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut program_traces,
                &mut side_note,
            );
        }
        assert_chip::<Chips>(traces, None, Some(program_traces.finalize()));
    }
}
