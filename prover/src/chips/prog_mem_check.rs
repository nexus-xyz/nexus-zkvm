use num_traits::One;

use nexus_vm::WORD_SIZE;
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use crate::{
    column::Column,
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::TraceEval, sidenote::SideNote, utils::FromBaseFields, ProgramStep, Traces},
    traits::MachineChip,
};

/// A Chip for program memory checking
///
/// ProgMemCheckChip needs to be located after CpuChip

pub struct ProgramMemCheckChip;

impl MachineChip for ProgramMemCheckChip {
    /// Fills `ProgPrevCtr` columns
    ///
    /// Assumes other chips have written to `Pc` on the current row
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &ProgramStep,
        side_note: &mut SideNote,
    ) {
        if !vm_step.step.is_padding {
            let pc = traces.column(row_idx, Column::Pc);
            let pc = u32::from_base_fields(pc);
            let last_access_counter = side_note
                .program_mem_check
                .last_access_counter
                .get(&pc)
                .unwrap_or(&0u32);
            traces.fill_columns(row_idx, *last_access_counter, Column::ProgCtrPrev);
            let new_access_counter = last_access_counter
                .checked_add(1)
                .expect("access counter overflow");
            traces.fill_columns(row_idx, new_access_counter, Column::ProgCtrCur);
            // Compute and fill carry flags
            let last_counter_bytes = last_access_counter.to_le_bytes();
            let mut carry_bits = [false; WORD_SIZE];
            let mut incremented_bytes = [0u8; WORD_SIZE];
            (incremented_bytes[0], carry_bits[0]) = last_counter_bytes[0].overflowing_add(1);
            for i in 1..WORD_SIZE {
                // Add the bytes and the previous carry
                (incremented_bytes[i], carry_bits[i]) =
                    last_counter_bytes[i].overflowing_add(carry_bits[i - 1] as u8);
            }
            assert!(!carry_bits[WORD_SIZE - 1]); // Check against overflow
            assert_eq!(u32::from_le_bytes(incremented_bytes), new_access_counter);
            traces.fill_columns(row_idx, carry_bits, Column::ProgCtrCarry);
            side_note
                .program_mem_check
                .last_access_counter
                .insert(pc, new_access_counter);
            // Note: no need to udpate the access counter for pc + {1,2,3}. They are not used.
            let instruction_word = traces.column(row_idx, Column::InstrVal);
            let instruction_word = u32::from_base_fields(instruction_word);
            let known_instruction_word = side_note
                .program_mem_check
                .accessed_program_memory
                .insert(pc, instruction_word);
            known_instruction_word
                .and_then(|known_word| Some(assert_eq!(known_word, instruction_word)));
        }
        // Use accessed_program_memory sidenote to fill in the final program memory contents
        if row_idx == traces.num_rows() - 1 {
            assert!(
                side_note.program_mem_check.accessed_program_memory.len() <= 1 << traces.log_size(),
                "More Pc access than the size of trace, unexpected."
            );
            let mut final_program_row_idx: usize = 0;
            for (pc, instruction_word) in side_note.program_mem_check.accessed_program_memory.iter()
            {
                traces.fill_columns(final_program_row_idx, *pc, Column::PrgMemoryPc);
                traces.fill_columns(
                    final_program_row_idx,
                    *instruction_word,
                    Column::PrgMemoryWord,
                );
                let counter = side_note
                    .program_mem_check
                    .last_access_counter
                    .get(pc)
                    .expect("counter not found with an accessed Pc");
                traces.fill_columns(final_program_row_idx, *counter, Column::FinalPrgMemoryCtr);
                traces.fill_columns(final_program_row_idx, true, Column::PrgMemoryFlag);
                final_program_row_idx += 1;
            }
        }
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let _ = lookup_elements;
        // Constrain PrgCurCtr = PrgPrevCtr + 1
        let (_, [is_padding]) = trace_eval.column_eval(Column::IsPadding);
        let (_, prg_prev_ctr) = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrPrev);
        let (_, prg_cur_ctr) = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrCur);
        let (_, prg_ctr_carry) = trace_eval.column_eval::<WORD_SIZE>(Column::ProgCtrCarry);
        let modulus = E::F::from((1u32 << 8).into());
        for i in 0..WORD_SIZE {
            let carry = i
                .checked_sub(1)
                .map(|j| prg_ctr_carry[j].clone())
                .unwrap_or(E::F::one());

            // prg_cur_ctr[i] + prg_ctr_carry[i] * 2^8 = prg_prev_ctr[i] + h1[i - 1] (or 1 if i == 0)
            eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (prg_cur_ctr[i].clone() + prg_ctr_carry[i].clone() * modulus.clone()
                        - (prg_prev_ctr[i].clone() + carry)),
            );
        }
        // Don't allow overflow
        eval.add_constraint(prg_ctr_carry[WORD_SIZE - 1].clone());
        // TODO: implement
    }
}
#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip},
        trace::{utils::IntoBaseFields, PreprocessedTraces},
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

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
    fn test_prog_mem_check_add_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let mut side_note = SideNote::default();

        let program_steps = vm_traces.blocks.into_iter().map(|block| {
            let regs = block.regs;
            assert_eq!(block.steps.len(), 1);
            ProgramStep {
                regs,
                step: block.steps[0].clone(),
            }
        });
        let num_steps = program_steps.clone().count();
        assert_eq!(num_steps, basic_block[0].len());
        let trace_steps = program_steps
            .chain(std::iter::repeat(ProgramStep::padding()))
            .take(traces.num_rows());

        for (row_idx, program_step) in trace_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            CpuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

            // Fill in the main trace of the ProgMemCheckChip
            ProgramMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
            );

            // Fill in the main trace of the AddChip
            AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }

        for i in 0..num_steps {
            assert_eq!(
                traces.column(i, Column::ProgCtrPrev),
                0u32.into_base_fields()
            );
            assert_eq!(
                traces.column(i, Column::ProgCtrCur),
                1u32.into_base_fields()
            );
            assert_eq!(
                traces.column(i, Column::ProgCtrCarry),
                [0u8; WORD_SIZE].into_base_fields()
            );
        }
        for item in side_note.program_mem_check.last_access_counter.iter() {
            assert_eq!(*item.1, 1, "unexpected number of accesses to Pc");
        }
        traces.assert_as_original_trace(|eval, trace_eval| {
            let dummy_lookup_elements = LookupElements::dummy();
            CpuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            ProgramMemCheckChip::add_constraints(eval, trace_eval, &dummy_lookup_elements)
        });
    }
}
