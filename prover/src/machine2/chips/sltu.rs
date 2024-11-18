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

// Support SLTU opcode.
pub struct SltuChip;

struct ExecutionResult {
    borrow_bits: [u32; WORD_SIZE],
    helper_bytes: [u32; WORD_SIZE],
    rd_is_x0: bool,
}

impl SltuChip {
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let result = program_step
            .get_result()
            .expect("Slt instruction must have a result");
        let rd_is_x0 = program_step.is_value_a_x0();

        // Recompute 32-bit result from 8-bit limbs.
        // 1. Break the computation to 8-bit limbs.
        // 2. Compute the diff and borrow of each limb.
        // 3. Check that the final result matches the expected result.

        // Step 1. Break the computation to 8-bit limbs.
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut helper1_bytes = [0u8; WORD_SIZE];
        let mut borrow = [false; WORD_SIZE];

        // Step 2. Compute the diff and borrow of each limb.
        let (diff, c0) = value_b[0].overflowing_sub(value_c[0]);
        borrow[0] = c0;
        helper1_bytes[0] = diff;

        // Process the remaining bytes
        for i in 1..WORD_SIZE {
            // Add the bytes and the previous borrow
            let (diff, b1) = value_b[i].overflowing_sub(borrow[i - 1] as u8);
            let (diff, b2) = diff.overflowing_sub(value_c[i]);

            // There can't be 2 borrow in: a - b - cary, at most either c1 or c2 is true.
            borrow[i] = b1 || b2;
            helper1_bytes[i] = diff;
        }
        let mut rd_bytes = [0u8; WORD_SIZE];
        rd_bytes[0] = borrow[3] as u8;

        // Step 3. Check that the final result matches the expected result.
        assert_eq!(rd_bytes, result);

        // Map borrow bits to 0/1 values, and expand to 32-bit words.
        let borrow_bits: [u32; WORD_SIZE] = borrow.map(|c| c as u32);
        let helper_bytes = helper1_bytes.map(|b| b as u32);

        ExecutionResult {
            borrow_bits,
            helper_bytes,
            rd_is_x0,
        }
    }
}

impl MachineChip for SltuChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SLTU)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            helper_bytes,
            rd_is_x0,
        } = Self::execute(vm_step);

        let helper_col = trace_column_mut!(traces, row_idx, Helper1);
        for (i, b) in helper_bytes.iter().enumerate() {
            *helper_col[i] = BaseField::from(*b);
        }
        let borrow_col = trace_column_mut!(traces, row_idx, CarryFlag);
        for (i, b) in borrow_bits.iter().enumerate() {
            *borrow_col[i] = BaseField::from(*b);
        }
        let rd_col = trace_column_mut!(traces, row_idx, ValueA);
        *rd_col[0] = BaseField::from(borrow_bits[3]);
        let rd_effective_col = trace_column_mut!(traces, row_idx, ValueAEffective);
        *rd_effective_col[0] = if rd_is_x0 {
            BaseField::zero()
        } else {
            BaseField::from(borrow_bits[3])
        };
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        let (_, is_sltu) = trace_eval!(trace_eval, IsSltu);
        let is_sltu = is_sltu[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        // Reusing the CarryFlag as borrow flag.
        let (_, borrow_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, rs1_val) = trace_eval!(trace_eval, ValueB);
        let (_, rs2_val) = trace_eval!(trace_eval, ValueC);
        let (_, rd_val) = trace_eval!(trace_eval, ValueA);
        let (_, helper1_val) = trace_eval!(trace_eval, Helper1);

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
                        - (rs1_val[i].clone() - rs2_val[i].clone() - borrow)),
            );

            match i {
                0 =>
                // SLTU rd[0] = borrow[3]
                {
                    eval.add_constraint(
                        is_sltu.clone() * (rd_val[i].clone() - borrow_flag[3].clone()),
                    )
                }
                1..=3 =>
                // SLTU rd[1,2,3] = 0
                {
                    eval.add_constraint(is_sltu.clone() * rd_val[i].clone())
                }
                _ => panic!("never reached"),
            }
        }
        // TODO: range check CarryFlag to be in {0, 1}.
        // TODO: range check r{s1,s2}_val[i] to be in [0, 255].
        // TODO: range check helper1_val[i] to be in [0, 255].
        // TODO: range check rd_val[i] to be in {0, 1}.
        // TODO: constrain ValueAEffective in CpuChip.
    }
}

#[cfg(test)]
mod test {
    use crate::machine2::chips::{AddChip, CpuChip}; // needed for ADDI to put a non-zero value in a register

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = 8;

    #[rustfmt::skip]
    fn setup_basic_block_ir() -> Vec<BasicBlock>
    {
        let basic_block = BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1, InstructionType::IType),
            // x2 = x1 < x0
            // x3 = x2 < x1 ... and so on
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 0, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 3, 2, 1, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 4, 3, 2, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 5, 4, 3, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 6, 5, 4, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 7, 6, 5, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 8, 7, 6, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 9, 8, 7, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 10, 9, 8, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 11, 10, 9, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 12, 11, 10, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 13, 12, 11, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 14, 13, 12, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 15, 14, 13, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 16, 15, 14, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 17, 16, 15, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 18, 17, 16, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 19, 18, 17, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 20, 19, 18, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 21, 20, 19, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 22, 21, 20, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 23, 22, 21, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 24, 23, 22, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 25, 24, 23, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 26, 25, 24, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 27, 26, 25, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 28, 27, 26, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 29, 28, 27, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 30, 29, 28, InstructionType::RType),
            Instruction::new(Opcode::from(BuiltinOpcode::SLTU), 31, 30, 29, InstructionType::RType),
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
        let mut row_idx = 0;

        // We iterate each block in the trace for each instruction
        for trace in vm_traces.blocks.iter() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // Now fill in the traces with ValueA and CarryFlags
                CpuChip::fill_main_trace(&mut traces, row_idx, &program_step);
                // AddChip::fill_main_trace() needs to be called because the first step is ADDI.
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step);
                SltuChip::fill_main_trace(&mut traces, row_idx, &program_step);

                row_idx += 1;
            }
        }

        traces.assert_as_original_trace(|eval, trace_eval| {
            AddChip::add_constraints(eval, trace_eval);
            SltuChip::add_constraints(eval, trace_eval);
        });
    }
}
