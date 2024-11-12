use num_traits::Zero;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_common::cpu::Registers;
use nexus_vm::{
    riscv::{BuiltinOpcode, Register},
    WORD_SIZE,
};

use crate::machine2::{
    column::Column::{self, *},
    trace::{
        eval::{trace_eval, TraceEval},
        trace_column_mut, ProgramStep, Traces,
    },
    traits::MachineChip,
};

// Support ADD and ADDI opcodes.
pub struct AddChip;

impl AddChip {
    fn decode(program_step: &ProgramStep) -> [[u8; WORD_SIZE]; 2] {
        let regs = &program_step.regs;
        let step = &program_step.step;
        let instruction = &step.instruction;

        // TODO: handle no-op case when rd = 0.
        assert!(instruction.op_a != Register::X0);

        let rs1 = regs.read(instruction.op_b);
        let rs2 = match step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ADD) => regs.read(Register::from(instruction.op_c as u8)),
            Some(BuiltinOpcode::ADDI) => instruction.op_c,
            _ => panic!("Invalid Opcode"),
        };

        // Break the computation to 8-bit limbs.
        let rs1_limbs = rs1.to_le_bytes();
        let rs2_limbs = rs2.to_le_bytes();

        [rs1_limbs, rs2_limbs]
    }
    fn execute(program_step: &ProgramStep) -> [[u32; WORD_SIZE]; 2] {
        let step = &program_step.step;
        let instruction = &step.instruction;
        let result = step.result.expect("Instruction does not have result");

        // TODO: handle no-op case when rd = 0.
        assert!(instruction.op_a != Register::X0);

        // Recompute 32-bit result from 8-bit limbs.
        // 1. Break the computation to 8-bit limbs.
        // 2. Compute the sum and carry of each limb.
        // 3. Check that the final result matches the expected result.

        // Step 1. Break the computation to 8-bit limbs.
        let [rs1_bytes, rs2_bytes] = Self::decode(program_step);

        let mut rd_bytes = [0u8; WORD_SIZE];
        let mut carry = [false; WORD_SIZE];

        // Step 2. Compute the sum and carry of each limb.
        let (sum, c0) = rs1_bytes[0].overflowing_add(rs2_bytes[0]);
        carry[0] = c0;
        rd_bytes[0] = sum;

        // Process the remaining bytes
        for i in 1..WORD_SIZE {
            // Add the bytes and the previous carry
            let (sum, c1) = rs1_bytes[i].overflowing_add(carry[i - 1] as u8);
            let (sum, c2) = sum.overflowing_add(rs2_bytes[i]);

            // There can't be 2 carry in: a + b + cary, either c1 or c2 is true.
            carry[i] = c1 || c2;
            rd_bytes[i] = sum;
        }

        // Step 3. Check that the final result matches the expected result.
        assert_eq!(rd_bytes, result.to_le_bytes());

        // Map carry bits to 0/1 values, and expand to 32-bit words.
        let carry_bits: [u32; WORD_SIZE] = carry.map(|c| c as u32);
        let rd_bytes = rd_bytes.map(|b| b as u32);

        [carry_bits, rd_bytes]
    }
}

impl MachineChip for AddChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI)
        ) {
            return;
        }

        let [carry_bytes, rd_bytes] = Self::execute(vm_step);

        let rd_col = trace_column_mut!(traces, row_idx, ValueA);
        for (i, b) in rd_bytes.iter().enumerate() {
            *rd_col[i] = BaseField::from(*b);
        }
        let carry_col = trace_column_mut!(traces, row_idx, CarryFlag);
        for (i, c) in carry_bytes.iter().enumerate() {
            *carry_col[i] = BaseField::from(*c);
        }
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        let (_, is_add) = trace_eval!(trace_eval, IsAdd);
        let is_add = is_add[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let (_, carry_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, rs1_val) = trace_eval!(trace_eval, ValueB);
        let (_, rs2_val) = trace_eval!(trace_eval, ValueC);
        let (_, rd_val) = trace_eval!(trace_eval, ValueA);

        for i in 0..WORD_SIZE {
            let carry = i
                .checked_sub(1)
                .map(|j| carry_flag[j].clone())
                .unwrap_or(E::F::zero());

            // ADD a, b, c
            // rdval[i] + h1[i] * 2^8 = rs1val[i] + rs2val[i] + h1[i - 1]
            eval.add_constraint(
                is_add.clone()
                    * (rd_val[i].clone() + carry_flag[i].clone() * modulus.clone()
                        - (rs1_val[i].clone() + rs2_val[i].clone() + carry)),
            );
        }
        // Range checks should differentiate ADD and ADDI cases, as immediate values are smaller.
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace::k_trace_direct,
    };
    use stwo_prover::{
        constraint_framework::assert_constraints,
        core::{
            backend::CpuBackend,
            pcs::TreeVec,
            poly::{
                circle::{CanonicCoset, CircleEvaluation},
                BitReversedOrder,
            },
        },
    };

    const LOG_SIZE: u32 = 6;

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
        let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
        let mut row_idx = 0;

        // We iterate each block in the trace and add constrain for each instruction
        for trace in vm_traces.blocks.iter() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // TODO: The CPU will have a nice interface to fill ValueB and ValueC.
                // for now, we have to write the fill step manually.
                {
                    let [rs1_bytes, rs2_bytes] = AddChip::decode(&program_step);

                    // Fill ValueB and ValueC to the main trace
                    let r1_col = trace_column_mut!(traces, row_idx, ValueB);
                    for (i, b) in rs1_bytes.iter().enumerate() {
                        *r1_col[i] = BaseField::from(*b as u32);
                    }
                    let r2_col = trace_column_mut!(traces, row_idx, ValueC);
                    for (i, b) in rs2_bytes.iter().enumerate() {
                        *r2_col[i] = BaseField::from(*b as u32);
                    }
                }

                // Now fill in the traces with ValueA and CarryFlags
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step);

                row_idx += 1;
            }
        }

        // Convert traces to the format expected by assert_constraints
        let traces: Vec<CircleEvaluation<_, _, _>> = traces
            .into_inner()
            .into_iter()
            .map(|eval| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, eval))
            .collect();

        let traces = TreeVec::new(vec![traces]);
        let trace_polys = traces.map(|trace| {
            trace
                .into_iter()
                .map(|c| c.interpolate())
                .collect::<Vec<_>>()
        });

        // Now check the constraints to make sure they're satisfied
        assert_constraints(&trace_polys, CanonicCoset::new(LOG_SIZE), |mut eval| {
            let trace_eval = TraceEval::new(&mut eval);
            AddChip::add_constraints(&mut eval, &trace_eval);
        });
    }
}
