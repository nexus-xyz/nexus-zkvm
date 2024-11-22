use num_traits::{One, Zero};
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::machine2::{
    chips::SubChip,
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        BoolWord, ProgramStep, Traces, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

pub struct ExecutionResult {
    pub borrow_bits: BoolWord,
    pub diff_bytes: Word,
    pub result: Word,
    /// true when destination register is writable (not X0)
    pub value_a_effective_flag: bool,
}

// Support SLTU opcode.
pub struct SltuChip;

impl ExecuteChip for SltuChip {
    type ExecutionResult = ExecutionResult;
    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let super::sub::ExecutionResult {
            borrow_bits,
            diff_bytes,
            value_a_effective_flag,
        } = SubChip::execute(program_step);
        let result = [borrow_bits[3] as u8, 0, 0, 0];
        ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
            value_a_effective_flag,
        }
    }
}

impl MachineChip for SltuChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        if vm_step.step.is_padding {
            return;
        }
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SLTU)
        ) {
            return;
        }

        let ExecutionResult {
            borrow_bits,
            diff_bytes,
            result,
            value_a_effective_flag,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, &diff_bytes, Helper1);
        traces.fill_columns_bool(row_idx, &borrow_bits, CarryFlag);

        debug_assert_eq!(result, vm_step.get_result().expect("STLU must have result"));

        traces.fill_columns(row_idx, &result, ValueA);
        traces.fill_effective_columns(row_idx, &result, ValueAEffective, value_a_effective_flag);
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

    const LOG_SIZE: u32 = Traces::MIN_LOG_SIZE;

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
        // Constraints about ValueAEffectiveFlagAux require that non-zero values be written in ValueAEffectiveFlagAux on every row.
        for more_row_idx in row_idx..(1 << LOG_SIZE) {
            CpuChip::fill_main_trace(&mut traces, more_row_idx, &ProgramStep::padding());
        }
        traces.assert_as_original_trace(|eval, trace_eval| {
            let dummy_lookup_elements = LookupElements::dummy();
            CpuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            AddChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
            SltuChip::add_constraints(eval, trace_eval, &dummy_lookup_elements);
        });
    }
}
