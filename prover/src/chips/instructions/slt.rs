use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::FieldExpOps};

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

// Support SLT and SLTI opcode.
pub struct SltChip;

impl ExecuteChip for SltChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let super::sub::ExecutionResult {
            borrow_bits,
            diff_bytes,
        } = SubChip::execute(program_step);

        // Extract signed bits of b and c
        let sgn_b = program_step.get_sgn_b();
        let sgn_c = program_step.get_sgn_c();

        let result = match (sgn_b, sgn_c) {
            (false, false) | (true, true) => [borrow_bits[3] as u8, 0, 0, 0],
            (false, true) => [0, 0, 0, 0],
            (true, false) => [1, 0, 0, 0],
        };

        ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
        }
    }
}

impl MachineChip for SltChip {
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
            Some(BuiltinOpcode::SLT) | Some(BuiltinOpcode::SLTI)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
        } = Self::execute(vm_step);

        // Fill Helper2 and Helper3 to the main trace
        let mut helper_b = vm_step.get_value_b();
        helper_b[WORD_SIZE - 1] &= 0x7f;

        let (mut helper_c, _) = vm_step.get_value_c();
        helper_c[WORD_SIZE - 1] &= 0x7f;

        traces.fill_columns(row_idx, helper_b, Helper2);
        traces.fill_columns(row_idx, helper_c, Helper3);

        // Fill SgnB and SgnC to the main trace
        let sgn_b = vm_step.get_sgn_b();
        traces.fill_columns(row_idx, sgn_b, SgnB);

        let sgn_c = vm_step.get_sgn_c();
        traces.fill_columns(row_idx, sgn_c, SgnC);

        traces.fill_columns(row_idx, diff_bytes, Helper1);
        traces.fill_columns(row_idx, borrow_bits, CarryFlag);

        assert_eq!(result, vm_step.get_result().expect("STL must have result"));

        traces.fill_columns(row_idx, result, ValueA);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let is_slt = trace_eval!(trace_eval, IsSlt);
        let is_slt = is_slt[0].clone();

        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());
        // modulues for 7-bit
        let modulus_7 = E::F::from(128u32.into());

        // Reusing the CarryFlag as borrow flag.
        let borrow_flag = trace_eval!(trace_eval, CarryFlag);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let value_a = trace_eval!(trace_eval, ValueA);
        let sgn_b = trace_eval!(trace_eval, SgnB);
        let sgn_c = trace_eval!(trace_eval, SgnC);
        let helper1_val = trace_eval!(trace_eval, Helper1);
        let helper2_val = trace_eval!(trace_eval, Helper2);
        let helper3_val = trace_eval!(trace_eval, Helper3);

        // h_1[0] + h_1[1] * 256 - borrow[1] * 2^{16} = rs1val[0] + rs1val[1] * 256 - rs2val[i] - rs2val[1] * 256
        eval.add_constraint(
            is_slt.clone()
                * (helper1_val[0].clone() + helper1_val[1].clone() * modulus.clone()
                    - borrow_flag[1].clone() * modulus.clone().pow(2)
                    - (value_b[0].clone() + value_b[1].clone() * modulus.clone()
                        - value_c[0].clone()
                        - value_c[1].clone() * modulus.clone())),
        );

        // h_1[2] + h_1[3] * 256 - borrow[3] * 2^{16} = rs1val[2] + rs1val[3] * 256 - rs2val[2] - rs2val[3] * 256 - borrow[1]
        eval.add_constraint(
            is_slt.clone()
                * (helper1_val[2].clone() + helper1_val[3].clone() * modulus.clone()
                    - borrow_flag[3].clone() * modulus.clone().pow(2)
                    - (value_b[2].clone() + value_b[3].clone() * modulus.clone()
                        - value_c[2].clone()
                        - value_c[3].clone() * modulus.clone()
                        - borrow_flag[1].clone())),
        );

        // Computing a_val from sltu_flag (borrow_flag[3]) and sign bits sgnb and sgnc
        // is_slt・ (sgnb・(1-sgnc) + ltu_flag・(sgnb・sgnc+(1-sgnb)・(1-sgnc)) - a_val_1) =0
        // is_slt・(a_val_2) = 0
        // is_slt・(a_val_3) = 0
        // is_slt・(a_val_4) = 0
        for i in 0..WORD_SIZE {
            if i == 0 {
                eval.add_constraint(
                    is_slt.clone()
                        * (sgn_b[0].clone() * (E::F::one() - sgn_c[0].clone())
                            + borrow_flag[3].clone()
                                * (sgn_b[0].clone() * sgn_c[0].clone()
                                    + (E::F::one() - sgn_b[0].clone())
                                        * (E::F::one() - sgn_c[0].clone()))
                            - value_a[0].clone()),
                );
            } else {
                eval.add_constraint(is_slt.clone() * value_a[i].clone())
            }
        }

        // is_slt * (h2[3] + sgn_b * 2^7 - b_val[3]) = 0
        eval.add_constraint(
            is_slt.clone()
                * (modulus_7.clone() * sgn_b[0].clone() + helper2_val[3].clone()
                    - value_b[3].clone()),
        );
        // is_slt * (h3[3] + sgn_c * 2^7 - c_val[3]) = 0
        eval.add_constraint(
            is_slt.clone()
                * (modulus_7.clone() * sgn_c[0].clone() + helper3_val[3].clone()
                    - value_c[3].clone()),
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
            // Set x0 = 0 (default constant)
            // Set x1 = 2000 (smaller positive number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 2000),
            // Set x2 = 4000 (larger positive number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 4000),
            // Set x3 = -2000 (smaller negative number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 3, 0, 1),
            // Set x4 = -4000 (larger negative number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 2),
            // Case 1: Smaller Positive < Larger Positive
            // x5 = 1 because 2000 < 4000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 5, 1, 2),
            // Case 2: Larger Positive > Smaller Positive
            // x6 = 0 because 4000 < 2000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 6, 2, 1),
            // Case 3: Larger Negative < Smaller Negative
            // x7 = 1 because -4000 < -2000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 7, 4, 3),
            // Case 4: Smaller Negative > Larger Negative
            // x8 = 0 because -2000 < -4000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 8, 3, 4),
            // Case 5: Positive < Negative (should always be false)
            // x9 = 0 because 2000 < -2000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 9, 1, 3),
            // Case 6: Negative < Positive (should always be true)
            // x10 = 1 because -2000 < 2000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 10, 3, 1),
            // Case 7: Equal positive numbers
            // x11 = 0 because 2000 < 2000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 11, 1, 1),
            // Case 8: Equal negative numbers
            // x12 = 0 because -2000 < -2000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 12, 3, 3),
            // Case 9: Zero and positive
            // x13 = 1 because 0 < 2000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 13, 0, 1),
            // Case 10: Zero and negative
            // x14 = 0 because 0 < -2000 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 14, 0, 3),
            // Case 11: Largest possible negative vs smallest possible negative
            // Set x15 = 0x80000000 (smallest negative 32-bit number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 15, 0, 1), // 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), //  2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), //  4
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), //  8
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 32
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 64
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 28
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 56
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 12
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 24
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 48
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 96
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 92
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 84
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 68
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 36
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 72
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 44
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 88
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 76
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 52
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 04
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 08
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 16
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 32
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 64
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 28
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 56
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 12
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // 24
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15), // x15 = -0)
            // Set x16 = -1 (largest negative 32-bit number)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 16, 0, 1),
            // x17 = 1 because -2147483648 < -1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLT), 17, 15, 16),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_stl_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            SltChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
