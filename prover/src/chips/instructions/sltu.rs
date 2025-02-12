use num_traits::Zero;
use stwo_prover::constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    chips::SubChip,
    column::Column::{self, *},
    components::AllLookupElements,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
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

        assert_eq!(result, vm_step.get_result().expect("STLU must have result"));

        traces.fill_columns_bytes(row_idx, &result, ValueA);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let is_sltu = trace_eval!(trace_eval, IsSltu);
        let is_sltu = is_sltu[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        // Reusing the CarryFlag as borrow flag.
        let borrow_flag = trace_eval!(trace_eval, CarryFlag);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);
        let helper1_val = trace_eval!(trace_eval, Helper1);

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

            // value_a[0] is constrained to be equal to the borrow flag, which is in {0, 1}.
            // Constraint value_a[1..=3] to equal 0.
            if i != 0 {
                eval.add_constraint(is_sltu.clone() * value_a[i].clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RegisterMemCheckChip},
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
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = 1 because 0 < 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 0, 1),
            // x2 = 0 because 1 < 1 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 1),
            // x2 = 0 because 1 < 0 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 0),
            // Testing SLTIU
            // x3 = 1 because 0 < 1 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 1),
            // x3 = 0 because 1 < 1 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 1),
            // x3 = 1 because 1 < 2 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 2),
            // x3 = 0 because 2 < 1 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 2, 1),
            // x3 = 1 because any number < 0xFFF (4095 in decimal, treated as unsigned)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 0xFFF),
            // x3 = 0 because 0 < 0 doesn't hold (testing with immediate 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 0),
            // Set x4 = 10 for further testing
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 10),
            // x3 = 1 because 10 < 15 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 15),
            // x3 = 0 because 10 < 5 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 5),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_stlu_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SltuChip,
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
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
