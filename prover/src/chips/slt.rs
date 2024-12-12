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
        traces: &mut Traces,
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

        debug_assert_eq!(result, vm_step.get_result().expect("STL must have result"));

        traces.fill_columns(row_idx, result, ValueA);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
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

        for i in 0..WORD_SIZE {
            let prev_borrow = i
                .checked_sub(1)
                .map(|j| borrow_flag[j].clone())
                .unwrap_or(E::F::zero());

            // SLT a, b, c
            // h_1[i] - borrow[i] * 2^8 = rs1val[i] - rs2val[i] - borrow[i - 1]
            eval.add_constraint(
                is_slt.clone()
                    * (helper1_val[i].clone()
                        - borrow_flag[i].clone() * modulus.clone()
                        - (value_b[i].clone() - value_c[i].clone() - prev_borrow)),
            );
        }

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

        // TODO: range check CarryFlag to be in {0, 1}.
        // TODO: range check rd_val[i] to be in {0, 1}.
        // TODO: constrain ValueAEffective in CpuChip.
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, RegisterMemCheckChip, SubChip},
        test_utils::assert_chip,
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
            // Set x0 = 0 (default constant)
            // Set x1 = 2000 (smaller positive number)
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 2000, InstructionType::IType),
            // Set x2 = 4000 (larger positive number)
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 4000, InstructionType::IType),
            // Set x3 = -2000 (smaller negative number)
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 3, 0, 1, InstructionType::RType),
            // Set x4 = -4000 (larger negative number)
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 4, 0, 2, InstructionType::RType),

            // Case 1: Smaller Positive < Larger Positive
            // x5 = 1 because 2000 < 4000
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 5, 1, 2, InstructionType::RType),

            // Case 2: Larger Positive > Smaller Positive
            // x6 = 0 because 4000 < 2000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 6, 2, 1, InstructionType::RType),

            // Case 3: Larger Negative < Smaller Negative
            // x7 = 1 because -4000 < -2000
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 7, 4, 3, InstructionType::RType),

            // Case 4: Smaller Negative > Larger Negative
            // x8 = 0 because -2000 < -4000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 8, 3, 4, InstructionType::RType),

            // Case 5: Positive < Negative (should always be false)
            // x9 = 0 because 2000 < -2000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 9, 1, 3, InstructionType::RType),

            // Case 6: Negative < Positive (should always be true)
            // x10 = 1 because -2000 < 2000
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 10, 3, 1, InstructionType::RType),

            // Case 7: Equal positive numbers
            // x11 = 0 because 2000 < 2000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 11, 1, 1, InstructionType::RType),

            // Case 8: Equal negative numbers
            // x12 = 0 because -2000 < -2000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 12, 3, 3, InstructionType::RType),

            // Case 9: Zero and positive
            // x13 = 1 because 0 < 2000
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 13, 0, 1, InstructionType::RType),

            // Case 10: Zero and negative
            // x14 = 0 because 0 < -2000 doesn't hold
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 14, 0, 3, InstructionType::RType),

            // Case 11: Largest possible negative vs smallest possible negative
            // Set x15 = 0x80000000 (smallest negative 32-bit number)
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 15, 0, 1, InstructionType::IType),
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 2
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 4
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 8
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 16
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 32
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 64
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 128
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 256
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 512
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 1024
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 2048
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 4096
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 8192
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 16384
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 32768
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 65536
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 131072
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 262144
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 524288
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 1048576
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 2097152
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 4194304
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 8388608
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 16777216
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 33554432
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 67108864
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 134217728
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 268435456
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 536870912
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = 1073741824
            Instruction::new(Opcode::from(BuiltinOpcode::ADD), 15, 15, 15, InstructionType::RType), // x15 = -2147483648 (0x80000000)

            // Set x16 = -1 (largest negative 32-bit number)
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 16, 0, 1, InstructionType::RType),

            // x17 = 1 because -2147483648 < -1
            Instruction::new(Opcode::from(BuiltinOpcode::SLT), 17, 15, 16, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_stl_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;
        type Chips = (CpuChip, AddChip, SubChip, SltChip, RegisterMemCheckChip);

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let mut side_note = SideNote::default();

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, None);
    }
}
