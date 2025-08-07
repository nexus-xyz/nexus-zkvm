use num_traits::One;
use stwo::core::fields::{m31::BaseField, FieldExpOps};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self, *},
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

use super::add::{self};

pub struct ExecutionResult {
    pub diff_bytes: Word,
    pub borrow_bits: [bool; 2], // At 16-bit boudaries.
    pub pc_next: Word,
    pub carry_bits: [bool; 2], // At 16-bit boundaries
    pub lt_flag: bool,
    pub h2: Word,
    pub h3: Word,
}

pub struct BltChip;

impl ExecuteChip for BltChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let sgn_a = program_step.get_sgn_a();
        let sgn_b = program_step.get_sgn_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        let (diff_bytes, borrow_bits) = super::sub::subtract_with_borrow(value_a, value_b);

        let result = match (sgn_a, sgn_b) {
            (false, false) | (true, true) => borrow_bits[3],
            (false, true) => false,
            (true, false) => true,
        };

        // lt_flag is equal to result
        let (pc_next, carry_bits) = if result {
            // a < b is true: pc_next = pc + imm
            add::add_with_carries(pc, imm)
        } else {
            // a >= b is true: pc_next = pc + 4
            add::add_with_carries(pc, 4u32.to_le_bytes())
        };
        let mut h2 = value_a;
        let mut h3 = value_b;
        // h2 and h3 are value_a and value_b with the sign bit cleared
        h2[WORD_SIZE - 1] &= 0x7f;
        h3[WORD_SIZE - 1] &= 0x7f;

        let borrow_bits = [borrow_bits[1], borrow_bits[3]];
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            diff_bytes,
            borrow_bits,
            pc_next,
            carry_bits,
            lt_flag: result,
            h2,
            h3,
        }
    }
}

impl MachineChip for BltChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return,
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::BLT)
        ) {
            return;
        }

        let ExecutionResult {
            diff_bytes,
            borrow_bits,
            pc_next,
            carry_bits,
            lt_flag,
            h2,
            h3,
        } = Self::execute(vm_step);

        traces.fill_columns(row_idx, diff_bytes, Column::Helper1);
        traces.fill_columns(row_idx, borrow_bits, Column::BorrowFlag);
        traces.fill_columns(row_idx, h2, Column::Helper2);
        traces.fill_columns(row_idx, h3, Column::Helper3);
        traces.fill_columns(row_idx, lt_flag, Column::LtFlag);

        // Fill valueA
        traces.fill_columns(row_idx, vm_step.get_value_a(), Column::ValueA);

        // Fill PcNext and CarryFlag, since Pc and Immediate are filled to the main trace in CPU.
        traces.fill_columns(row_idx, pc_next, Column::PcNext);
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let modulus = E::F::from(256u32.into());
        let modulus_7_inv = E::F::from(BaseField::from(128u32).inverse());
        let value_a = trace_eval!(trace_eval, ValueA);
        let value_b = trace_eval!(trace_eval, ValueB);
        let value_c = trace_eval!(trace_eval, ValueC);
        let pc = trace_eval!(trace_eval, Column::Pc);
        let carry_bits = trace_eval!(trace_eval, Column::CarryFlag);
        let borrow_bits = trace_eval!(trace_eval, Column::BorrowFlag);
        let diff_bytes = trace_eval!(trace_eval, Column::Helper1);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let [is_blt] = trace_eval!(trace_eval, Column::IsBlt);
        let ltu_flag = borrow_bits[1].clone();
        let [lt_flag] = trace_eval!(trace_eval, Column::LtFlag);
        let h2 = trace_eval!(trace_eval, Column::Helper2);
        let h3 = trace_eval!(trace_eval, Column::Helper3);
        // sgn_a is taken to be abbreviation of (a_val_4 - h2) / 2^7
        let sgn_a =
            (value_a[WORD_SIZE - 1].clone() - h2[WORD_SIZE - 1].clone()) * modulus_7_inv.clone();
        // sgn_b is taken to be abbreviation of (b_val_4 - h3) / 2^7
        let sgn_b =
            (value_b[WORD_SIZE - 1].clone() - h3[WORD_SIZE - 1].clone()) * modulus_7_inv.clone();

        // is_blt・(a_val_1 + a_val_2 * 256 - b_val_1 - b_val_2 * 256 - h1_1 - h1_2 * 256 + borrow_1・2^{16}) = 0
        eval.add_constraint(
            is_blt.clone()
                * (value_a[0].clone() + value_a[1].clone() * modulus.clone()
                    - value_b[0].clone()
                    - value_b[1].clone() * modulus.clone()
                    - diff_bytes[0].clone()
                    - diff_bytes[1].clone() * modulus.clone()
                    + borrow_bits[0].clone() * modulus.clone().pow(2)),
        );
        // is_blt・(a_val_3 + a_val_4 * 256 - b_val_3 - b_val_4 * 256 - h1_3 - h1_4 * 256 + borrow_2・2^{16} - borrow_1) = 0
        eval.add_constraint(
            is_blt.clone()
                * (value_a[2].clone() + value_a[3].clone() * modulus.clone()
                    - value_b[2].clone()
                    - value_b[3].clone() * modulus.clone()
                    - diff_bytes[2].clone()
                    - diff_bytes[3].clone() * modulus.clone()
                    + borrow_bits[1].clone() * modulus.clone().pow(2)
                    - borrow_bits[0].clone()),
        );

        // is_blt・ (sgna・(1-sgnb) + ltu_flag・(sgna・sgnb+(1-sgna)・(1-sgnb)) - lt_flag) =0
        eval.add_constraint(
            is_blt.clone()
                * (sgn_a.clone() * (E::F::one() - sgn_b.clone())
                    + ltu_flag.clone()
                        * (sgn_a.clone() * sgn_b.clone()
                            + (E::F::one() - sgn_a.clone()) * (E::F::one() - sgn_b.clone()))
                    - lt_flag.clone()),
        );

        // Setting pc_next based on comparison result
        // pc_next=pc+c_val if lt_flag = 1
        // pc_next=pc+4 	if lt_flag = 0
        // is_blt・(lt_flag・(c_val_1 + c_val_2 * 256) + (1-lt_flag)・4 + pc_1 + pc_2 * 256 - carry_1·2^{16} - pc_next_1 - pc_next_2 * 256) =0
        eval.add_constraint(
            is_blt.clone()
                * (lt_flag.clone() * (value_c[0].clone() + value_c[1].clone() * modulus.clone())
                    + (E::F::one() - lt_flag.clone()) * E::F::from(4u32.into())
                    + pc[0].clone()
                    + pc[1].clone() * modulus.clone()
                    - carry_bits[0].clone() * modulus.clone().pow(2)
                    - pc_next[0].clone()
                    - pc_next[1].clone() * modulus.clone()),
        );
        // is_blt・(lt_flag・(c_val_3 + c_val_4 * 256) + pc_3 + pc_4 * 256 + carry_1 - carry_2·2^{16} - pc_next_3 - pc_next_4 * 256) = 0
        eval.add_constraint(
            is_blt.clone()
                * (lt_flag.clone() * (value_c[2].clone() + value_c[3].clone() * modulus.clone())
                    + pc[2].clone()
                    + pc[3].clone() * modulus.clone()
                    + carry_bits[0].clone()
                    - carry_bits[1].clone() * modulus.clone().pow(2)
                    - pc_next[2].clone()
                    - pc_next[3].clone() * modulus.clone()),
        );

        // sgn_a is 0 or 1
        eval.add_constraint(is_blt.clone() * (sgn_a.clone() * (E::F::one() - sgn_a.clone())));
        // sgn_b is 0 or 1
        eval.add_constraint(is_blt * (sgn_b.clone() * (E::F::one() - sgn_b.clone())));
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, SubChip,
        },
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set x10 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 10, 0, 1),
            // Set x1 = 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 10),
            // Set x2 = 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 20),
            // Set x3 = 10 (same as x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 10),
            // Set x4 = -10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 4, 0, 1),
            // Set x5 = -1 (0xFFFFFFFF as signed)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 5, 0, 10),
            // Case 1: BLT with equal values (should not branch)
            // BLT x1, x3, 0xff (should not branch as x1 < x3 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 1, 3, 0xff),
            // Case 2: BLT with different values (should branch)
            // BLT x1, x2, 12 (branch to PC + 12 as x1 < x2 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 1, 2, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 3: BLT with zero and positive (should branch)
            // BLT x0, x1, 8 (branch to PC + 8 as x0 < x1 is true)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 1, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Case 4: BLT with zero and zero (should not branch)
            // BLT x0, x0, 8 (should not branch as x0 < x0 is false)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 0, 0xff),
            // Case 5: BLT with negative and positive values (should branch)
            // BLT x4, x1, 8 (should branch as -10 < 10)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 4, 1, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 6: BLT with -1 and zero (should branch)
            // BLT x5, x0, 8 (should branch as -1 < 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 5, 0, 12),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            Instruction::unimpl(),
            // Case 7: BLT with zero and -1 (should not branch)
            // BLT x0, x5, 12 (should not branch as 0 > -1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BLT), 0, 5, 0xff),
            Instruction::nop(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_blt_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            SubChip,
            BltChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }

        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
