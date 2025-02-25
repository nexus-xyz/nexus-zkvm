use num_traits::Zero;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

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

// Support ADD and ADDI opcodes.
pub struct AddChip;

pub struct ExecutionResult {
    carry_bits: BoolWord,
    sum_bytes: Word,
}

pub fn add_with_carries(a: Word, b: Word) -> (Word, BoolWord) {
    let mut sum_bytes = [0u8; WORD_SIZE];
    let mut carry_bits = [false; WORD_SIZE];

    // Compute the sum and carry of each limb.
    let (sum, c0) = a[0].overflowing_add(b[0]);
    carry_bits[0] = c0;
    sum_bytes[0] = sum;
    // Process the remaining bytes
    for i in 1..WORD_SIZE {
        // Add the bytes and the previous carry
        let (sum, c1) = a[i].overflowing_add(carry_bits[i - 1] as u8);
        let (sum, c2) = sum.overflowing_add(b[i]);
        // There can't be 2 carry in: a + b + cary, either c1 or c2 is true.
        carry_bits[i] = c1 || c2;
        sum_bytes[i] = sum;
    }
    (sum_bytes, carry_bits)
}

impl ExecuteChip for AddChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        // Recompute 32-bit result from 8-bit limbs.
        let (sum_bytes, carry_bits) = add_with_carries(value_b, value_c);

        ExecutionResult {
            carry_bits,
            sum_bytes,
        }
    }
}

impl MachineChip for AddChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI)
        ) {
            return;
        }

        let ExecutionResult {
            carry_bits,
            sum_bytes,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        assert_eq!(
            sum_bytes,
            vm_step
                .get_result()
                .expect("ADD/ADDI instruction must have a result")
        );
        traces.fill_columns_bytes(row_idx, &sum_bytes, ValueA);
        traces.fill_columns(row_idx, carry_bits, CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let is_add = trace_eval!(trace_eval, IsAdd);
        let is_add = is_add[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let carry_flag = trace_eval!(trace_eval, CarryFlag);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);

        for i in 0..WORD_SIZE {
            let carry = i
                .checked_sub(1)
                .map(|j| carry_flag[j].clone())
                .unwrap_or(E::F::zero());

            // ADD a, b, c
            // rdval[i] + h1[i] * 2^8 = rs1val[i] + rs2val[i] + h1[i - 1]
            eval.add_constraint(
                is_add.clone()
                    * (value_a[i].clone() + carry_flag[i].clone() * modulus.clone()
                        - (value_b[i].clone() + value_c[i].clone() + carry)),
            );
        }
    }
}

#[cfg(test)]
mod test {

    use crate::{
        chips::{
            CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip, RegisterMemCheckChip,
            TimestampChip,
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
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = x1 + x0
            // x3 = x2 + x1 ... and so on
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 7, 6, 5),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 8, 7, 6),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 9, 8, 7),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 10, 9, 8),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 11, 10, 9),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 12, 11, 10),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 13, 12, 11),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 14, 13, 12),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 14, 13),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 16, 15, 14),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 17, 16, 15),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 18, 17, 16),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 19, 18, 17),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 20, 19, 18),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 21, 20, 19),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 22, 21, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 23, 22, 21),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 24, 23, 22),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 25, 24, 23),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 26, 25, 24),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 27, 26, 25),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 28, 27, 26),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 29, 28, 27),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 30, 29, 28),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 31, 30, 29),
        ]);
        // The second basic block found some completeness issues in TimestampChip in the past.
        let basic_block_2 = BasicBlock::new(vec![
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADD),
                2,
                1,
                0
            );
            60
        ]);
        vec![basic_block, basic_block_2]
    }

    #[test]
    fn test_k_trace_constrained_add_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            TimestampChip,
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
        let program_trace = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_trace, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, Some(program_trace.finalize()));
    }
}
