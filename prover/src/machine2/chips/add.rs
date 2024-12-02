use num_traits::{One, Zero};
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::machine2::{
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
    /// true when destination register is writable (not X0)
    value_a_effective_flag: bool,
}

impl ExecuteChip for AddChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> ExecutionResult {
        let value_a_effective_flag = program_step.value_a_effectitve_flag();

        // Recompute 32-bit result from 8-bit limbs.

        // Step 1. Break the computation to 8-bit limbs
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let mut sum_bytes = [0u8; WORD_SIZE];
        let mut carry_bits = [false; WORD_SIZE];

        // Step 2. Compute the sum and carry of each limb.
        let (sum, c0) = value_b[0].overflowing_add(value_c[0]);
        carry_bits[0] = c0;
        sum_bytes[0] = sum;

        // Process the remaining bytes
        for i in 1..WORD_SIZE {
            // Add the bytes and the previous carry
            let (sum, c1) = value_b[i].overflowing_add(carry_bits[i - 1] as u8);
            let (sum, c2) = sum.overflowing_add(value_c[i]);

            // There can't be 2 carry in: a + b + cary, either c1 or c2 is true.
            carry_bits[i] = c1 || c2;
            sum_bytes[i] = sum;
        }

        ExecutionResult {
            carry_bits,
            sum_bytes,
            value_a_effective_flag,
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
            value_a_effective_flag,
        } = Self::execute(vm_step);

        // Before filling the trace, we check the result of 8-bit limbs is correct.
        debug_assert_eq!(
            sum_bytes,
            vm_step
                .get_result()
                .expect("ADD/ADDI instruction must have a result")
        );

        traces.fill_columns_bytes(row_idx, &sum_bytes, ValueA);
        traces.fill_effective_columns(row_idx, &sum_bytes, ValueAEffective, value_a_effective_flag);
        traces.fill_columns(row_idx, carry_bits, CarryFlag);
        traces.fill_columns_bytes(row_idx, &[1u8], Reg1Accessed);
        traces.fill_columns_bytes(row_idx, &[vm_step.step.instruction.op_b as u8], Reg1Address);
        if vm_step.step.instruction.opcode.builtin() == Some(BuiltinOpcode::ADD) {
            traces.fill_columns_bytes(row_idx, &[1u8], Reg2Accessed);
            traces.fill_columns_bytes(row_idx, &[vm_step.step.instruction.op_c as u8], Reg2Address);
        }
        traces.fill_columns_bytes(row_idx, &[1u8], Reg3Accessed);
        traces.fill_columns_bytes(row_idx, &[vm_step.step.instruction.op_a as u8], Reg3Address);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let (_, is_add) = trace_eval!(trace_eval, IsAdd);
        let is_add = is_add[0].clone();
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let (_, carry_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, value_b) = trace_eval!(trace_eval, ValueB);
        let (_, value_c) = trace_eval!(trace_eval, ValueC);
        let (_, value_a) = trace_eval!(trace_eval, ValueA);
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

        // Constrain Reg{1,2,3}Accessed
        let (_, [reg1_accessed]) = trace_eval!(trace_eval, Reg1Accessed);
        let (_, [reg2_accessed]) = trace_eval!(trace_eval, Reg2Accessed);
        let (_, [reg3_accessed]) = trace_eval!(trace_eval, Reg3Accessed);
        let (_, [imm_c]) = trace_eval!(trace_eval, ImmC);
        eval.add_constraint(is_add.clone() * (E::F::one() - reg1_accessed.clone()));
        eval.add_constraint(is_add.clone() * imm_c.clone() * reg2_accessed.clone());
        eval.add_constraint(
            is_add.clone() * (E::F::one() - imm_c) * (E::F::one() - reg2_accessed.clone()),
        );
        eval.add_constraint(is_add.clone() * (E::F::one() - reg3_accessed.clone()));

        // Constrain Reg{1,2,3}Address uniquely
        let (_, [is_add]) = trace_eval!(trace_eval, Column::IsAdd);
        let (_, [imm_c]) = trace_eval!(trace_eval, Column::ImmC);
        let (_, [op_a]) = trace_eval!(trace_eval, Column::OpA);
        let (_, [op_b]) = trace_eval!(trace_eval, Column::OpB);
        let (_, [op_c]) = trace_eval!(trace_eval, Column::OpC);
        let (_, [reg1_address]) = trace_eval!(trace_eval, Column::Reg1Address);
        let (_, [reg2_address]) = trace_eval!(trace_eval, Column::Reg2Address);
        let (_, [reg3_address]) = trace_eval!(trace_eval, Column::Reg3Address);
        eval.add_constraint(is_add.clone() * (op_b - reg1_address));
        eval.add_constraint(
            is_add.clone() * (E::F::one() - imm_c.clone()) * (op_c.clone() - reg2_address),
        );
        eval.add_constraint(is_add.clone() * imm_c * op_c);
        eval.add_constraint(is_add * (op_a - reg3_address));

        // TODO: special range check rs2_val[i] for ADDI case, because immediate values have a smaller range.
    }
}

#[cfg(test)]
mod test {
    use crate::machine2::{chips::CpuChip, trace::PreprocessedTraces};

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
        let mut side_note = SideNote::default();
        let mut row_idx = 0;

        // We iterate each block in the trace for each instruction
        for trace in vm_traces.blocks.iter() {
            let regs = trace.regs;
            for step in trace.steps.iter() {
                let program_step = ProgramStep {
                    regs,
                    step: step.clone(),
                };

                // Fill in the main trace with the ValueB, valueC and Opcode
                CpuChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

                // TODO: use RegisterMemCheckChip too, when it's ready

                // Now fill in the traces with ValueA and CarryFlags
                AddChip::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);

                row_idx += 1;
            }
        }
        // Constraints about ValueAEffectiveFlagAux require that non-zero values be written in ValueAEffectiveFlagAux on every row.
        for more_row_idx in row_idx..traces.num_rows() {
            CpuChip::fill_main_trace(
                &mut traces,
                more_row_idx,
                &ProgramStep::padding(),
                &mut side_note,
            );
        }
        traces.assert_as_original_trace(|eval, trace_eval| {
            let dummy_lookup_elements = LookupElements::dummy();
            CpuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            AddChip::add_constraints(eval, trace_eval, &dummy_lookup_elements)
        });
    }
}
