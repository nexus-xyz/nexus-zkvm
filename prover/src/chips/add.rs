use num_traits::Zero;
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        BoolWord, ProgramStep, Traces, Word,
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
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &ProgramStep,
        _side_note: &mut SideNote,
    ) {
        if vm_step.step.is_padding {
            return;
        }
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
        debug_assert_eq!(
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
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let (is_add, _) = trace_eval!(trace_eval, IsAdd);
        let is_add = is_add[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let (carry_flag, _) = trace_eval!(trace_eval, CarryFlag);
        let (value_b, _) = trace_eval!(trace_eval, ValueB);
        let (value_c, _) = trace_eval!(trace_eval, ValueC);
        let (value_a, _) = trace_eval!(trace_eval, ValueA);
        // TODO: constrain ValueAEffective to be zero or equal to ValueA depending on whether rd is x0 (in CPU chip, when it exists)

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

        // TODO: special range check rs2_val[i] for ADDI case, because immediate values have a smaller range.
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{CpuChip, RegisterMemCheckChip},
        test_utils::assert_chip,
        trace::{program::iter_program_steps, PreprocessedTraces},
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    // PreprocessedTraces::MIN_LOG_SIZE makes the test consume more than 40 seconds.
    const LOG_SIZE: u32 = 8;

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
    fn test_k_trace_constrained_add_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut side_note = SideNote::default();

        for (row_idx, program_step) in program_steps.enumerate() {
            // Fill in the main trace with the ValueB, valueC and Opcode
            CpuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

            // Now fill in the traces with ValueA and CarryFlags
            AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

            // The test uses registers, so register memory checking should happen too
            RegisterMemCheckChip::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
            );
        }
        let mut preprocessed_column = PreprocessedTraces::empty(LOG_SIZE);
        preprocessed_column.fill_is_first();
        preprocessed_column.fill_is_first32();
        preprocessed_column.fill_row_idx();
        preprocessed_column.fill_timestamps();
        assert_chip::<(CpuChip, AddChip, RegisterMemCheckChip)>(traces, Some(preprocessed_column));
    }
}
