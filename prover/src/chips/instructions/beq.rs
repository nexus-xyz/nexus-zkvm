use num_traits::One;
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::fields::{
        m31::{BaseField, M31},
        FieldExpOps,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTracesBuilder,
        sidenote::SideNote,
        BoolWord, ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

use super::add;

pub struct ExecutionResult {
    pub neq_flag: bool,        // Flag indicating if a_val != b_val
    pub neq_12_flag: bool,     // Flag indicating if (a_val_1, a_val_2) != (b_val_1, b_val_2)
    pub neq_34_flag: bool,     // Flag indicating if (a_val_3, a_val_4) != (b_val_3, b_val_4)
    pub result: Word,          // Next program counter (pc_next)
    pub carry_bits: BoolWord,  // Carry bits for addition
    pub neq_aux: [M31; 2],     // Difference between a_val and b_val
    pub neq_aux_inv: [M31; 2], // Inverse of the difference
}

pub struct BeqChip;

impl ExecuteChip for BeqChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();
        let pc_l = u16::from_be_bytes([pc[0], pc[1]]) as u32;
        let pc_h = u16::from_be_bytes([pc[2], pc[3]]) as u32;
        let value_a_l = u16::from_le_bytes([value_a[0], value_a[1]]) as u32;
        let value_b_l = u16::from_le_bytes([value_b[0], value_b[1]]) as u32;
        let value_a_h = u16::from_le_bytes([value_a[2], value_a[3]]) as u32;
        let value_b_h = u16::from_le_bytes([value_b[2], value_b[3]]) as u32;

        let (pc_next, carry_bits) = if value_a == value_b {
            add::add_with_carries(pc, imm)
        } else {
            add::add_with_carries(pc, 4u32.to_le_bytes())
        };

        let neq_flag = value_a != value_b;
        let neq_12_flag = value_a_l != value_b_l;
        let neq_34_flag = value_a_h != value_b_h;

        // Calculate neq_{12,34}_flag_aux and its inverse mod M31
        let (neq_12_flag_aux, neq_12_flag_aux_inv) = if neq_12_flag {
            // When neq_12_flag == 1
            // value_a_[0] ≠ value_b_[0] or value_a_[1] ≠ value_b_[1]
            // neq_12_flag_aux = 1 / (value_a_l - value_b_l)
            // neq_12_flag_aux_inv = value_a_l - value_b_l
            let aux_inv = BaseField::from(value_a_l) - BaseField::from(value_b_l);
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        } else {
            // Use PC as it's guaranteed to be non-zero.
            // Even if PC is 0, use 1 as a fallback value.
            let aux_inv = BaseField::from(pc_l.max(1));
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        };

        let (neq_34_flag_aux, neq_34_flag_aux_inv) = if neq_34_flag {
            // When neq_34_flag == 1
            // value_a_[2] ≠ value_b_[2] or value_a_[3] ≠ value_b_[3]
            // neq_34_flag_aux = 1 / (value_a_h - value_b_h)
            // neq_34_flag_aux_inv = value_a_h - value_b_h
            let aux_inv = BaseField::from(value_a_h) - BaseField::from(value_b_h);
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        } else {
            // Use PC as it's guaranteed to be non-zero.
            // Even if PC is 0, use 1 as a fallback value.
            let aux_inv = BaseField::from(pc_h.max(1));
            let aux = aux_inv.inverse();
            (aux, aux_inv)
        };

        let neq_aux = [neq_12_flag_aux, neq_34_flag_aux];
        let neq_aux_inv = [neq_12_flag_aux_inv, neq_34_flag_aux_inv];

        ExecutionResult {
            neq_flag,
            neq_12_flag,
            neq_34_flag,
            result: pc_next,
            carry_bits,
            neq_aux,
            neq_aux_inv,
        }
    }
}

impl MachineChip for BeqChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::BEQ)
        ) {
            return;
        }

        let ExecutionResult {
            neq_flag,
            neq_12_flag,
            neq_34_flag,
            result: pc_next,
            carry_bits,
            neq_aux,
            neq_aux_inv,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, neq_flag, Column::Neq);
        traces.fill_columns(row_idx, neq_12_flag, Column::Neq12);
        traces.fill_columns(row_idx, neq_34_flag, Column::Neq34);

        // Fill valueA
        traces.fill_columns(row_idx, vm_step.get_value_a(), Column::ValueA);

        // TODO: it's possible to pack neq_{12,34}_flag into diff and store in Helper
        // NeqAux = 1 / (valueA - valueB); If valueA == valueB, NeqAux is random non-zero value.
        traces.fill_columns_base_field(row_idx, [neq_aux[0]].as_slice(), Column::Neq12Aux);
        traces.fill_columns_base_field(row_idx, [neq_aux[1]].as_slice(), Column::Neq34Aux);
        // NeqAuxInv = 1/NeqAux.
        traces.fill_columns_base_field(row_idx, [neq_aux_inv[0]].as_slice(), Column::Neq12AuxInv);
        traces.fill_columns_base_field(row_idx, [neq_aux_inv[1]].as_slice(), Column::Neq34AuxInv);

        // Fill PcNext and CarryFlag, since Pc and Immediate are filled to the main trace in CPU.
        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let modulus = E::F::from(256u32.into());
        let neq_flag = trace_eval!(trace_eval, Column::Neq);
        let neq_12_flag = trace_eval!(trace_eval, Column::Neq12);
        let neq_34_flag = trace_eval!(trace_eval, Column::Neq34);
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let carry_bits = trace_eval!(trace_eval, Column::CarryFlag);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let is_beq = trace_eval!(trace_eval, Column::IsBeq);
        let is_beq = is_beq[0].clone();

        let neq_12_flag_aux = trace_eval!(trace_eval, Column::Neq12Aux);
        let neq_34_flag_aux = trace_eval!(trace_eval, Column::Neq34Aux);
        let neq_12_flag_aux_inv = trace_eval!(trace_eval, Column::Neq12AuxInv);
        let neq_34_flag_aux_inv = trace_eval!(trace_eval, Column::Neq34AuxInv);

        // is_beq・((a_val_1 + a_val_2·2^8 − b_val_1 - b_val_2·2^8)・neq_12_flag_aux - neq_12_flag) = 0
        eval.add_constraint(
            is_beq.clone()
                * ((value_a[0].clone() + value_a[1].clone() * modulus.clone()
                    - value_b[0].clone()
                    - value_b[1].clone() * modulus.clone())
                    * neq_12_flag_aux[0].clone()
                    - neq_12_flag[0].clone()),
        );

        // is_beq・((a_val_3 + a_val_4·2^8 − b_val_3 - b_val_4·2^8)・neq_34_flag_aux - neq_34_flag) = 0
        eval.add_constraint(
            is_beq.clone()
                * ((value_a[2].clone() + value_a[3].clone() * modulus.clone()
                    - value_b[2].clone()
                    - value_b[3].clone() * modulus.clone())
                    * neq_34_flag_aux[0].clone()
                    - neq_34_flag[0].clone()),
        );

        // is_beq・(neq_12_flag)・(1-neq_12_flag) = 0
        eval.add_constraint(
            is_beq.clone() * neq_12_flag[0].clone() * (E::F::one() - neq_12_flag[0].clone()),
        );
        // is_beq・(neq_34_flag)・(1-neq_34_flag) = 0
        eval.add_constraint(
            is_beq.clone() * neq_34_flag[0].clone() * (E::F::one() - neq_34_flag[0].clone()),
        );

        // Enforcing neq_flag_aux_i ≠ 0
        // is_beq・(neq_12_flag_aux・neq_12_flag_aux_inv - 1) = 0
        eval.add_constraint(
            is_beq.clone()
                * (neq_12_flag_aux[0].clone() * neq_12_flag_aux_inv[0].clone() - E::F::one()),
        );
        // is_beq・(neq_34_flag_aux・neq_34_flag_aux_inv - 1) = 0
        eval.add_constraint(
            is_beq.clone()
                * (neq_34_flag_aux[0].clone() * neq_34_flag_aux_inv[0].clone() - E::F::one()),
        );

        // is_beq・((1-neq_12_flag)・(1-neq_34_flag) - (1-neq_flag)) = 0
        eval.add_constraint(
            is_beq.clone()
                * ((E::F::one() - neq_12_flag[0].clone()) * (E::F::one() - neq_34_flag[0].clone())
                    - (E::F::one() - neq_flag[0].clone())),
        );

        // Setting pc_next based on comparison result
        // pc_next=pc+c_val if neq_flag = 0
        // pc_next=pc+4 	if neq_flag = 1
        // carry_{1,2,3,4} used for carry handling
        // is_beq・((1 - neq_flag)・c_val_1 + neq_flag・4 + pc_1 - carry_1·2^8 - pc_next_1) = 0
        eval.add_constraint(
            is_beq.clone()
                * ((E::F::one() - neq_flag[0].clone()) * value_c[0].clone()
                    + neq_flag[0].clone() * E::F::from(4u32.into())
                    + pc[0].clone()
                    - carry_bits[0].clone() * modulus.clone()
                    - pc_next[0].clone()),
        );

        // is_beq・((1 - neq_flag)・c_val_2 + pc_2 + carry_1 - carry_2·2^8 - pc_next_2) = 0
        // is_beq・((1 - neq_flag)・c_val_3 + pc_3 + carry_2 - carry_3·2^8 - pc_next_3) = 0
        // is_beq・((1 - neq_flag)・c_val_4 + pc_4 + carry_3 - carry_4·2^8 - pc_next_4) = 0
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_beq.clone()
                    * ((E::F::one() - neq_flag[0].clone()) * value_c[i].clone()
                        + pc[i].clone()
                        + carry_bits[i - 1].clone()
                        - carry_bits[i].clone() * modulus.clone()
                        - pc_next[i].clone()),
            );
        }

        // carry_{1,2,3,4} ∈ {0,1} is enforced in RangeBoolChip
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, CpuChip, ProgramMemCheckChip, RegisterMemCheckChip, SubChip},
        test_utils::assert_chip,
        trace::{
            preprocessed::PreprocessedBuilder,
            program::iter_program_steps,
            program_trace::{self},
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::{Emulator, HarvardEmulator},
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = 8; // PreprocessedBuilder::MIN_LOG_SIZE; makes the test more than a minute long.

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Case 1: BEQ with different values (should not branch)
            // BEQ x1, x2, 0xff (branch to PC + 0xff if x1 == x2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 2, 0xff),
            // Case 2: BEQ with equal values (should branch)
            // BEQ x1, x3, 12 (should branch as x1 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 1, 3, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BEQ with zero and non-zero (should not branch)
            // BEQ x0, x1, 0xff (branch to PC + 0xff if x0 == x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 0, 1, 0xff),
            // Case 4: BEQ with zero and zero (should branch)
            // BEQ x0, x0, 8 (should branch as x0 == x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 0, 0, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::nop(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_beq_instructions() {
        type Chips = (
            CpuChip,
            AddChip,
            SubChip,
            BeqChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let emulator = HarvardEmulator::from_basic_blocks(&basic_block);
        let program_memory = emulator.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_trace = program_trace::ProgramTracesBuilder::new(LOG_SIZE, program_memory);
        let mut side_note = SideNote::new(
            &program_trace,
            &emulator,
            vm_traces.memory_layout.public_output_addresses(),
        );
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut program_trace,
                &mut side_note,
            );
        }

        let mut preprocessed_column = PreprocessedBuilder::empty(LOG_SIZE);
        preprocessed_column.fill_is_first();
        preprocessed_column.fill_is_first32();
        preprocessed_column.fill_row_idx();
        preprocessed_column.fill_timestamps();
        assert_chip::<Chips>(
            traces,
            Some(preprocessed_column),
            Some(program_trace.finalize()),
        );
    }
}
