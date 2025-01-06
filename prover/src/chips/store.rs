use nexus_vm::{memory::MemoryRecord, riscv::BuiltinOpcode};
use num_traits::One;

use crate::{
    column::Column::{
        self, IsSb, IsSh, IsSw, Ram1Accessed, Ram1TsPrev, Ram1ValCur, Ram1ValPrev, Ram2Accessed,
        Ram2TsPrev, Ram2ValCur, Ram2ValPrev, Ram3Accessed, Ram3TsPrev, Ram3ValCur, Ram3ValPrev,
        Ram4Accessed, Ram4TsPrev, Ram4ValCur, Ram4ValPrev,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::trace_eval, program_trace::ProgramTraces, sidenote::SideNote, ProgramStep,
        TracesBuilder, Word,
    },
    traits::MachineChip,
};

use super::add::add_with_carries;

// Support SB, SH and SW opcodes
pub struct StoreChip;

impl MachineChip for StoreChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return,
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SB) | Some(BuiltinOpcode::SH) | Some(BuiltinOpcode::SW)
        ) {
            return;
        }

        let value_a = vm_step.get_value_a();
        traces.fill_columns(row_idx, value_a, Column::ValueA);
        traces.fill_columns(row_idx, value_a, Column::ValueAEffective);
        let (offset, effective_bits) = vm_step.get_value_c();
        assert_eq!(effective_bits, 12);
        let (ram_base_address, carry_bits) = add_with_carries(value_a, offset);
        traces.fill_columns(row_idx, ram_base_address, Column::RamBaseAddr);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
        let clk = row_idx as u32 + 1;
        for memory_record in vm_step.step.memory_records.iter() {
            assert!(
                matches!(memory_record, MemoryRecord::StoreRecord(..)),
                "no StoreRecord in store instruction"
            );
            assert_eq!(
                memory_record.get_timestamp(),
                (row_idx as u32 + 1),
                "timestamp mismatch"
            );
            assert_eq!(memory_record.get_timestamp(), clk, "timestamp mismatch");
            let byte_address = memory_record.get_address();
            assert_eq!(
                byte_address,
                u32::from_le_bytes(ram_base_address),
                "address mismatch"
            );

            let size = memory_record.get_size() as usize;

            assert!(
                (memory_record.get_prev_value().unwrap() as usize) < { 1usize } << (size * 8),
                "a memory operation contains a too big prev value"
            );
            assert!(
                (memory_record.get_value() as usize) < { 1usize } << (size * 8),
                "a memory operation contains a too big value"
            );

            let cur_value: Word = memory_record.get_value().to_le_bytes();
            let prev_value: Word = memory_record
                .get_prev_value()
                .expect("Store operation should carry a previous value")
                .to_le_bytes();

            for (i, (val_cur, val_prev, ts_prev, accessed)) in [
                (Ram1ValCur, Ram1ValPrev, Ram1TsPrev, Ram1Accessed),
                (Ram2ValCur, Ram2ValPrev, Ram2TsPrev, Ram2Accessed),
                (Ram3ValCur, Ram3ValPrev, Ram3TsPrev, Ram3Accessed),
                (Ram4ValCur, Ram4ValPrev, Ram4TsPrev, Ram4Accessed),
            ]
            .into_iter()
            .take(size)
            .enumerate()
            {
                traces.fill_columns(row_idx, cur_value[i], val_cur);
                traces.fill_columns(row_idx, prev_value[i], val_prev);
                traces.fill_columns(row_idx, memory_record.get_prev_timestamp(), ts_prev);
                traces.fill_columns(row_idx, true, accessed);
            }
        }
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &stwo_prover::constraint_framework::logup::LookupElements<
            MAX_LOOKUP_TUPLE_SIZE,
        >,
    ) {
        let [is_sb] = trace_eval!(trace_eval, IsSb);
        let [is_sh] = trace_eval!(trace_eval, IsSh);
        let [is_sw] = trace_eval!(trace_eval, IsSw);
        // Constrain the value of Ram1Accessed
        let [ram1_accessed] = trace_eval!(trace_eval, Ram1Accessed);
        eval.add_constraint(
            (is_sb.clone() + is_sh.clone() + is_sw.clone()) * (E::F::one() - ram1_accessed),
        );
        // Constrain the value of Ram2Accessed
        let [ram2_accessed] = trace_eval!(trace_eval, Ram2Accessed);
        eval.add_constraint(is_sb.clone() * ram2_accessed.clone());
        eval.add_constraint((is_sh.clone() + is_sw.clone()) * (E::F::one() - ram2_accessed));
        // Constrain the value of Ram3Accessed
        let [ram3_accessed] = trace_eval!(trace_eval, Ram3Accessed);
        eval.add_constraint((is_sb.clone() + is_sh.clone()) * ram3_accessed.clone());
        eval.add_constraint(is_sw.clone() * (E::F::one() - ram3_accessed));
        // Constrain the value of Ram4Accessed
        let [ram4_accessed] = trace_eval!(trace_eval, Ram4Accessed);
        eval.add_constraint((is_sb + is_sh) * ram4_accessed.clone());
        eval.add_constraint(is_sw * (E::F::one() - ram4_accessed));

        // TODO: implement
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::{
            preprocessed::PreprocessedBuilder, program::iter_program_steps,
            program_trace::ProgramTraces,
        },
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    // PreprocessedTraces::MIN_LOG_SIZE makes the test consume more than 40 seconds.
    const LOG_SIZE: u32 = 8;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // First we create a usable address. heap start: 528392, heap end: 8917000
            // Aiming to create 0x81008
            // TODO: shrink the following sequence of ADDs using SLL when it's available
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // repeat doubling x1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x8
            // Copying x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x1000
            // Adding x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x10000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x80000
            // Adding x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            // Now x2 should be 0x81008
            // Seeting x3 to be 3
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 3),
            // Storing a byte *x3 = 3 to memory address *x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SB), 2, 3, 0),
            // Storing two-bytes *x3 = 3 to memory address *x2 + 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SH), 2, 3, 10),
            // Storing four-bytes *x3 = 3 to memory address *x2 + 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SW), 2, 3, 20),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_store_instructions() {
        type Chips = (CpuChip, AddChip, StoreChip, RegisterMemCheckChip);
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_trace = ProgramTraces::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &program_trace,
                &mut side_note,
            );
        }
        let mut preprocessed_column = PreprocessedBuilder::empty(LOG_SIZE);
        preprocessed_column.fill_is_first();
        preprocessed_column.fill_is_first32();
        preprocessed_column.fill_row_idx();
        preprocessed_column.fill_timestamps();
        assert_chip::<Chips>(traces, Some(preprocessed_column), Some(program_trace));
    }
}
