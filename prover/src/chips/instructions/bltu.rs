use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::FieldExpOps};

use nexus_vm::riscv::BuiltinOpcode;

use crate::{
    column::Column::{self, *},
    components::AllLookupElements,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

use super::add::{self};

pub struct ExecutionResult {
    pub diff_bytes: Word,
    pub borrow_bits: BoolWord,
    pub pc_next: Word,
    pub carry_bits: BoolWord,
}

pub struct BltuChip;

impl ExecuteChip for BltuChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        let (diff_bytes, borrow_bits) = super::sub::subtract_with_borrow(value_a, value_b);

        // ltu_flag is equal to borrow_bit[3]
        let (pc_next, carry_bits) = if borrow_bits[3] {
            // a < b is true: pc_next = pc + imm
            add::add_with_carries(pc, imm)
        } else {
            // a >= b is true: pc_next = pc + 4
            add::add_with_carries(pc, 4u32.to_le_bytes())
        };

        ExecutionResult {
            diff_bytes,
            borrow_bits,
            pc_next,
            carry_bits,
        }
    }
}

impl MachineChip for BltuChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return,
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::BLTU)
        ) {
            return;
        }

        let ExecutionResult {
            diff_bytes,
            borrow_bits,
            pc_next,
            carry_bits,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, diff_bytes, Column::Helper1);
        traces.fill_columns(row_idx, borrow_bits, Column::BorrowFlag);

        // Fill valueA
        traces.fill_columns(row_idx, vm_step.get_value_a(), Column::ValueA);

        // Fill PcNext and CarryFlag, since Pc and Immediate are filled to the main trace in CPU.
        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let modulus = E::F::from(256u32.into());
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let carry_bits = trace_eval!(trace_eval, Column::CarryFlag);
        let borrow_bits = trace_eval!(trace_eval, Column::BorrowFlag);
        let diff_bytes = trace_eval!(trace_eval, Column::Helper1);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let [is_bltu] = trace_eval!(trace_eval, Column::IsBltu);
        let ltu_flag = borrow_bits[3].clone();

        // is_bltu・(a_val_1 + a_val_2 * 256 - b_val_1 - b_val_2 * 256 - h1_1 - h1_2 * 256 + borrow_2・2^{16}) = 0
        eval.add_constraint(
            is_bltu.clone()
                * (value_a[0].clone() + value_a[1].clone() * modulus.clone()
                    - value_b[0].clone()
                    - value_b[1].clone() * modulus.clone()
                    - diff_bytes[0].clone()
                    - diff_bytes[1].clone() * modulus.clone()
                    + borrow_bits[1].clone() * modulus.clone().pow(2)),
        );
        // is_bltu・(a_val_3 + a_val_4 * 256 - b_val_3 - b_val_4 * 256 - h1_3 - h1_4 * 256 + borrow_4・2^{16} - borrow_2) = 0
        eval.add_constraint(
            is_bltu.clone()
                * (value_a[2].clone() + value_a[3].clone() * modulus.clone()
                    - value_b[2].clone()
                    - value_b[3].clone() * modulus.clone()
                    - diff_bytes[2].clone()
                    - diff_bytes[3].clone() * modulus.clone()
                    + borrow_bits[3].clone() * modulus.clone().pow(2)
                    - borrow_bits[1].clone()),
        );

        // is_bltu・(ltu_flag・(c_val_1 + c_val_2 * 256) + (1-ltu_flag)・4 + pc_1 + pc_2 * 256 - carry_2·2^{16} - pc_next_1 - pc_next_2 * 256) =0
        eval.add_constraint(
            is_bltu.clone()
                * (ltu_flag.clone() * (value_c[0].clone() + value_c[1].clone() * modulus.clone())
                    + (E::F::one() - ltu_flag.clone()) * E::F::from(4u32.into())
                    + pc[0].clone()
                    + pc[1].clone() * modulus.clone()
                    - carry_bits[1].clone() * modulus.clone().pow(2)
                    - pc_next[0].clone()
                    - pc_next[1].clone() * modulus.clone()),
        );
        // is_bltu・(ltu_flag・(c_val_3 + c_val_4 * 256) + pc_3 + pc_4 * 256 + carry_2 - carry_4·2^{16} - pc_next_3 - pc_next_4 * 256) = 0
        eval.add_constraint(
            is_bltu.clone()
                * (ltu_flag.clone() * (value_c[2].clone() + value_c[3].clone() * modulus.clone())
                    + pc[2].clone()
                    + pc[3].clone() * modulus.clone()
                    + carry_bits[1].clone()
                    - carry_bits[3].clone() * modulus.clone().pow(2)
                    - pc_next[2].clone()
                    - pc_next[3].clone() * modulus.clone()),
        );
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip, SubChip,
        },
        test_utils::assert_chip,
        trace::{
            preprocessed::PreprocessedBuilder, program::iter_program_steps,
            program_trace::ProgramTracesBuilder,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedBuilder::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x10 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 1),
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Set x5 = 0xFFFFFFFF (max unsigned value)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Case 1: BLTU with equal values (should not branch)
            // BLTU x1, x3, 0xff (should not branch as x1 < x3 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 1, 3, 0xff),
            // Case 2: BLTU with different values (should branch)
            // BLTU x1, x2, 12 (branch to PC + 12 as x1 < x2 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 1, 2, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BLTU with zero and non-zero (should branch)
            // BLTU x0, x1, 8 (branch to PC + 8 as x0 < x1 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 1, 8),
            // No-op instruction to fill the gap (should not be executed)
            Instruction::unimpl(),
            // Case 4: BLTU with zero and zero (should not branch)
            // BLTU x0, x0, 8 (should not branch as x0 < x0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 0, 0xff),
            // Case 5: BLTU with negative and positive values (should not branch)
            // BLTU x4, x1, 8 (should not branch as 0xfffffff6 > 10 unsigned)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 4, 1, 0xff),
            // Case 6: BLTU with max unsigned value and zero (should not branch)
            // BLTU x5, x0, 8 (should not branch as 0xFFFFFFFF > 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 5, 0, 0xff),
            // Case 7: BLTU with zero and max unsigned value (should branch)
            // BLTU x0, x5, 12 (branch to PC + 12 as 0 < 0xFFFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLTU), 0, 5, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            Instruction::nop(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_bltu_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            BltuChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_trace = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_trace, &view);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }

        assert_chip::<Chips>(traces, Some(program_trace.finalize()));
    }
}
