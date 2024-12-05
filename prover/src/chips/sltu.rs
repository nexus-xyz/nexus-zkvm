use num_traits::{One, Zero};
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    chips::SubChip,
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        BoolWord, ProgramStep, Traces, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

pub struct ExecutionResult {
    pub borrow_bits: BoolWord,
    pub diff_bytes: Word,
    pub result: Word,
}

// Support SLTU opcode.
pub struct SltuChip;

impl ExecuteChip for SltuChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let super::sub::ExecutionResult {
            borrow_bits,
            diff_bytes,
        } = SubChip::execute(program_step);
        let result = [borrow_bits[3] as u8, 0, 0, 0];
        ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
        }
    }
}

impl MachineChip for SltuChip {
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
            Some(BuiltinOpcode::SLTU) | Some(BuiltinOpcode::SLTIU)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
        } = Self::execute(vm_step);

        traces.fill_columns_bytes(row_idx, &diff_bytes, Helper1);
        traces.fill_columns(row_idx, borrow_bits, CarryFlag);

        debug_assert_eq!(result, vm_step.get_result().expect("STLU must have result"));

        traces.fill_columns_bytes(row_idx, &result, ValueA);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let (_, is_sltu) = trace_eval!(trace_eval, IsSltu);
        let is_sltu = is_sltu[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        // Reusing the CarryFlag as borrow flag.
        let (_, borrow_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, value_b) = trace_eval!(trace_eval, ValueB);
        let (_, value_c) = trace_eval!(trace_eval, ValueC);
        let (_, value_a) = trace_eval!(trace_eval, ValueA);
        let (_, helper1_val) = trace_eval!(trace_eval, Helper1);

        // Assert boorrow_flag[3] is equal to value_a[0].
        // So the last iteration of the loop below match
        // is_sltu・(b_val_4 - c_val_4 - h1_4 + a_val_1・2^8 - borrow_3) = 0
        eval.add_constraint(is_sltu.clone() * (borrow_flag[3].clone() - value_a[0].clone()));

        for i in 0..WORD_SIZE {
            let borrow = i
                .checked_sub(1)
                .map(|j| borrow_flag[j].clone())
                .unwrap_or(E::F::zero());

            // SLTU a, b, c
            // h_1[i] - h1[i] * 2^8 = rs1val[i] - rs2val[i] - borrow[i - 1]
            eval.add_constraint(
                is_sltu.clone()
                    * (helper1_val[i].clone()
                        - borrow_flag[i].clone() * modulus.clone()
                        - (value_b[i].clone() - value_c[i].clone() - borrow)),
            );

            // Enforce value_a[0] is in {0, 1} and value_a[1..=3] are 0.
            if i == 0 {
                eval.add_constraint(
                    is_sltu.clone() * (value_a[0].clone() - E::F::one()) * value_a[0].clone(),
                );
            } else {
                eval.add_constraint(is_sltu.clone() * value_a[i].clone());
            }
        }

        // TODO: range check rd_val[i] to be in {0, 1}.
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip}, // needed for ADDI to put a non-zero value in a register
        trace::{program::iter_program_steps, PreprocessedTraces},
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
            // x2 = 1 because 0 < 1
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 2, 0, 1, InstructionType::RType),
            // x2 = 0 because 1 < 1 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 1, InstructionType::RType),
            // x2 = 0 because 1 < 0 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 0, InstructionType::RType),

            // Testing SLTIU
            // x3 = 1 because 0 < 1 (immediate)
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 1, InstructionType::IType),
            // x3 = 0 because 1 < 1 (immediate) doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 1, InstructionType::IType),
            // x3 = 1 because 1 < 2 (immediate)
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 2, InstructionType::IType),
            // x3 = 0 because 2 < 1 (immediate) doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 2, 1, InstructionType::IType),
            // x3 = 1 because any number < 0xFFF (4095 in decimal, treated as unsigned)
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 0xFFF, InstructionType::IType),
            // x3 = 0 because 0 < 0 doesn't hold (testing with immediate 0)
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 0, InstructionType::IType),
            // Set x4 = 10 for further testing
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 10, InstructionType::IType),
            // x3 = 1 because 10 < 15 (immediate)
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 15, InstructionType::IType),
            // x3 = 0 because 10 < 5 (immediate) doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 5, InstructionType::IType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_stlu_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut side_note = SideNote::default();

        for (row_idx, program_step) in program_steps.enumerate() {
            // Now fill in the traces with ValueA and CarryFlags
            CpuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
            // AddChip::fill_main_trace() needs to be called because the first step is ADDI.
            AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
            SltuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        traces.assert_as_original_trace(|eval, trace_eval| {
            let dummy_lookup_elements = LookupElements::dummy();
            CpuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            AddChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            SltuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
        });
    }
}
