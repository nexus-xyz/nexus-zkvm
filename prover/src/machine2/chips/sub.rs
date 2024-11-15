use num_traits::Zero;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::machine2::{
    column::Column::{self, *},
    trace::{
        eval::{trace_eval, TraceEval},
        trace_column_mut, ProgramStep, Traces,
    },
    traits::MachineChip,
};

// Support SUB opcodes.
pub struct SubChip;

struct ExecutionResult {
    borrow_bits: [u32; WORD_SIZE],
    diff_bytes: [u32; WORD_SIZE],
    rd_is_x0: bool,
}

impl SubChip {
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let result = program_step
            .get_result()
            .expect("Instruction does not have result");
        let rd_is_x0 = program_step.is_value_a_x0();

        // Recompute 32-bit result from 8-bit limbs.
        // 1. Break the computation to 8-bit limbs.
        // 2. Compute the difference and borrow_bits of each limb.
        // 3. Check that the final result matches the expected result.

        // Step 1. Break the computation to 8-bit limbs.
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut value_a = [0u8; WORD_SIZE];
        let mut borrow = [false; WORD_SIZE];

        // Step 2. Compute the difference and borrow of each limb.
        let (diff, c0) = value_b[0].overflowing_sub(value_c[0]);
        borrow[0] = c0;
        value_a[0] = diff;

        // Process the remaining difference bytes
        for i in 1..WORD_SIZE {
            // Subtract the bytes and the previous borrow
            let (diff, b1) = value_b[i].overflowing_sub(borrow[i - 1] as u8);
            let (diff, b2) = diff.overflowing_sub(value_c[i]);

            // There can't be 2 borrow in: a - b - borrow, either b1 or b2 is true.
            borrow[i] = b1 || b2;
            value_a[i] = diff;
        }

        // Step 3. Check that the final result matches the expected result.
        assert_eq!(value_a, result);

        // Map borrow bits to 0/1 values, and expand to 32-bit words.
        let borrow_bits: [u32; WORD_SIZE] = borrow.map(|c| c as u32);
        let diff_bytes = value_a.map(|b| b as u32);

        ExecutionResult {
            borrow_bits,
            diff_bytes,
            rd_is_x0,
        }
    }
}

impl MachineChip for SubChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SUB)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            diff_bytes,
            rd_is_x0,
        } = Self::execute(vm_step);

        let value_a_col = trace_column_mut!(traces, row_idx, ValueA);
        for (i, b) in diff_bytes.iter().enumerate() {
            *value_a_col[i] = BaseField::from(*b);
        }

        let value_a_effective = trace_column_mut!(traces, row_idx, ValueAEffective);
        for (i, b) in diff_bytes.iter().enumerate() {
            *value_a_effective[i] = if rd_is_x0 {
                BaseField::zero()
            } else {
                BaseField::from(*b)
            };
        }

        let carry_col = trace_column_mut!(traces, row_idx, CarryFlag);
        for (i, c) in borrow_bits.iter().enumerate() {
            *carry_col[i] = BaseField::from(*c);
        }
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        let (_, is_sub) = trace_eval!(trace_eval, IsSub);
        let is_sub = is_sub[0].clone();

        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let (_, borrow_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, rs1_val) = trace_eval!(trace_eval, ValueB);
        let (_, rs2_val) = trace_eval!(trace_eval, ValueC);
        let (_, rd_val) = trace_eval!(trace_eval, ValueA);
        // TODO: constrain ValueAEffective to be zero or equal to ValueA depending on whether rd is x0 (in CPU chip, when it exists)

        for i in 0..WORD_SIZE {
            let borrow = i
                .checked_sub(1)
                .map(|j| borrow_flag[j].clone())
                .unwrap_or(E::F::zero());

            // SUB a, b, c
            // rdval[i] - h1[i] * 2^8 = rs1val[i] - rs2val[i] - h1[i - 1]
            eval.add_constraint(
                is_sub.clone()
                    * (rd_val[i].clone()
                        - borrow_flag[i].clone() * modulus.clone()
                        - (rs1_val[i].clone() - rs2_val[i].clone() - borrow)),
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::machine2::chips::{cpu::CpuChip, AddChip};
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = 8;

    #[rustfmt::skip]
    fn setup_basic_block_ir() -> Vec<BasicBlock>
    {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1, there is no SUBI instruction
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 - x0
            // x3 = x2 - x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SUB), 31, 30, 29, InstructionType::RType),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_sub_instructions() {
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = Traces::new(LOG_SIZE);
        let mut row_idx = 0;

        // We iterate each block in the trace for each instruction
        for trace in vm_traces.blocks.iter() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // CpuChip will fill ValueB and ValueC
                CpuChip::fill_main_trace(&mut traces, row_idx, &program_step);

                // Now fill in the traces with ValueA and CarryFlags
                // The AddChip is here because the 1st instruction is ADDI, there is no SUBI
                // to replace ADDI, so 1st instruction is not handled by SubChip.
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step);
                SubChip::fill_main_trace(&mut traces, row_idx, &program_step);

                row_idx += 1;
            }
        }
        traces.assert_as_original_trace(|eval, trace_eval| {
            CpuChip::add_constraints(eval, trace_eval);
            AddChip::add_constraints(eval, trace_eval);
            SubChip::add_constraints(eval, trace_eval);
        });
    }
}
