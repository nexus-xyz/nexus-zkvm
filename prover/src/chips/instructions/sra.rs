use num_traits::{Euclid, One};
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::fields::m31::BaseField,
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};

use crate::{
    column::Column::{self},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        ProgramStep, TracesBuilder, Word,
    },
    traits::{ExecuteChip, MachineChip},
};

#[derive(Default)]
pub struct ExecutionResult {
    result: Word,
    srl: Word,
    shift_bits: [bool; 5],
    exp1_3: u8,
    h1: u8,
    h2: u8,
    rem: Word,
    rem_diff: Word,
    qt: Word,
    sgn_b: bool,
}

pub struct SraChip;

impl ExecuteChip for SraChip {
    type ExecutionResult = ExecutionResult;

    fn execute(program_step: &ProgramStep) -> Self::ExecutionResult {
        let result = program_step.get_result().expect("SRA must have result");
        let value_b = program_step.get_value_b();
        // We know that imm is in range: 0 -> 31, thus we only get the 1st limb
        let value_c = program_step.get_value_c().0;
        let imm = value_c[0];

        let h1 = imm >> 5;
        let exponent = imm & 0b111;
        let exp1_3 = 1 << exponent;
        let mut sh = [false; 5];
        sh[0] = (imm & 1) == 1;
        sh[1] = ((imm >> 1) & 1) == 1;
        sh[2] = ((imm >> 2) & 1) == 1;
        sh[3] = ((imm >> 3) & 1) == 1;
        sh[4] = ((imm >> 4) & 1) == 1;

        let mut rem = [0u8; WORD_SIZE];
        let mut rem_diff = [0u8; WORD_SIZE];
        let mut qt = [0u8; WORD_SIZE];
        let srl = u32::from_le_bytes(value_b) >> (imm & 0x1F);

        (qt[3], rem[3]) = value_b[3].div_rem_euclid(&exp1_3);
        for i in (0..WORD_SIZE - 1).rev() {
            let t = u16::from(value_b[i]) + (u16::from(rem[i + 1]) << 8);
            let (q, r) = t.div_rem_euclid(&(exp1_3 as u16));
            // It is guaranteed that q, r < 256
            rem[i] = r as u8;
            qt[i] = q as u8;
        }
        let sgn_b = program_step.get_sgn_b();
        let h2 = value_b[3] & 0b0111_1111;

        for i in 0..WORD_SIZE {
            rem_diff[i] = exp1_3 - 1 - rem[i];
        }

        Self::ExecutionResult {
            result,
            srl: srl.to_le_bytes(),
            shift_bits: sh,
            exp1_3,
            h1,
            h2,
            rem,
            rem_diff,
            qt,
            sgn_b,
        }
    }
}

impl MachineChip for SraChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SRA) | Some(BuiltinOpcode::SRAI)
        ) {
            return;
        }

        let ExecutionResult {
            result,
            srl,
            shift_bits,
            exp1_3,
            h1,
            h2,
            rem,
            rem_diff,
            qt,
            sgn_b,
        } = Self::execute(vm_step);

        // Exp is in the field M31
        let exp = BaseField::from(256u32 / u32::from(exp1_3));

        traces.fill_columns(row_idx, result, Column::ValueA);
        traces.fill_columns(row_idx, rem, Column::Rem);
        traces.fill_columns(row_idx, rem_diff, Column::RemDiff);
        traces.fill_columns(row_idx, qt, Column::Qt);
        traces.fill_columns(row_idx, [h1, 0u8, 0u8, 0u8], Column::Helper1);
        traces.fill_columns(row_idx, [h2, 0u8, 0u8, 0u8], Column::Helper2);
        traces.fill_columns(row_idx, srl, Column::Helper3);
        traces.fill_columns(row_idx, shift_bits[0], Column::ShiftBit1);
        traces.fill_columns(row_idx, shift_bits[1], Column::ShiftBit2);
        traces.fill_columns(row_idx, shift_bits[2], Column::ShiftBit3);
        traces.fill_columns(row_idx, shift_bits[3], Column::ShiftBit4);
        traces.fill_columns(row_idx, shift_bits[4], Column::ShiftBit5);
        traces.fill_columns(row_idx, exp1_3, Column::Exp1_3);
        traces.fill_columns(row_idx, exp, Column::Exp);
        traces.fill_columns(row_idx, sgn_b, Column::SgnB);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let modulus = E::F::from(256u32.into());
        let value_a = trace_eval!(trace_eval, Column::ValueA);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        let [sh1] = trace_eval!(trace_eval, Column::ShiftBit1);
        let [sh2] = trace_eval!(trace_eval, Column::ShiftBit2);
        let [sh3] = trace_eval!(trace_eval, Column::ShiftBit3);
        let [sh4] = trace_eval!(trace_eval, Column::ShiftBit4);
        let [sh5] = trace_eval!(trace_eval, Column::ShiftBit5);
        let [h1, _, _, _] = trace_eval!(trace_eval, Column::Helper1);
        let [h2, _, _, _] = trace_eval!(trace_eval, Column::Helper2);
        let srl = trace_eval!(trace_eval, Column::Helper3);
        let [exp1_3] = trace_eval!(trace_eval, Column::Exp1_3);
        let [exp] = trace_eval!(trace_eval, Column::Exp);
        let rem = trace_eval!(trace_eval, Column::Rem);
        let qt = trace_eval!(trace_eval, Column::Qt);
        let [is_sra] = trace_eval!(trace_eval, Column::IsSra);
        let [sgn_b] = trace_eval!(trace_eval, Column::SgnB);
        let rem_diff = trace_eval!(trace_eval, Column::RemDiff);

        // is_sra・(sh1 + sh2・2 + sh3・4 + sh4・8 + sh5・16 + h1・32 - c_val_1) = 0
        eval.add_constraint(
            is_sra.clone()
                * (sh1.clone()
                    + sh2.clone() * E::F::from(2u32.into())
                    + sh3.clone() * E::F::from(4u32.into())
                    + sh4.clone() * E::F::from(8u32.into())
                    + sh5.clone() * E::F::from(16u32.into())
                    + h1 * E::F::from(32u32.into())
                    - value_c[0].clone()),
        );

        // Computing exponent exp1_3 to perform temporary 3-bit right shift
        // is_sra・ ((sh1+1)・(3・sh2+1)・(15・sh3+1) - exp1_3) = 0
        eval.add_constraint(
            is_sra.clone()
                * ((sh1.clone() + E::F::one())
                    * (sh2.clone() * E::F::from(3u32.into()) + E::F::one())
                    * (sh3.clone() * E::F::from(15u32.into()) + E::F::one())
                    - exp1_3.clone()),
        );

        // Performing a temporary right shift using 3 lower bits of shift amount
        // is_sra・ (b_val_4 - rem4 - qt4・exp1_3) = 0
        // is_sra・ (b_val_3 + rem4・2^8 - rem3 - qt3・exp1_3) = 0
        // is_sra・ (b_val_2 + rem3・2^8 - rem2 - qt2・exp1_3) = 0
        // is_sra・ (b_val_1 + rem2・2^8 - rem1 - qt1・exp1_3) = 0
        eval.add_constraint(
            is_sra.clone() * (value_b[3].clone() - rem[3].clone() - qt[3].clone() * exp1_3.clone()),
        );
        for i in (0..WORD_SIZE - 1).rev() {
            eval.add_constraint(
                is_sra.clone()
                    * (value_b[i].clone() + rem[i + 1].clone() * modulus.clone()
                        - rem[i].clone()
                        - qt[i].clone() * exp1_3.clone()),
            );
        }

        // Extracting sign bit for b_val
        // is_sra・ (h2 + sgn・2^7 - b_val_4) = 0
        eval.add_constraint(
            is_sra.clone() * (h2 + sgn_b.clone() * E::F::from(128u32.into()) - value_b[3].clone()),
        );

        // Computing complete logical right shift using remaining bits of shift amount
        // is_sra・ (srl_4 - qt4・(1-sh4)・(1-sh5)) = 0
        // is_sra・ (srl_3 - qt3・(1-sh4)・(1-sh5)- qt4・(sh4)・(1-sh5)) = 0
        // is_sra・ (srl_2 - qt2・(1-sh4)・(1-sh5)- qt3・(sh4)・(1-sh5) - qt4・(1-sh4)・(sh5)) = 0
        // is_sra・ (srl_1 - qt1・(1-sh4)・(1-sh5)- qt2・(sh4)・(1-sh5) - qt3・(1-sh4)・(sh5) - qt4・(sh4)・(sh5)) = 0
        eval.add_constraint(
            is_sra.clone()
                * (srl[3].clone()
                    - qt[3].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_sra.clone()
                * (srl[2].clone()
                    - qt[2].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[3].clone() * sh4.clone() * (E::F::one() - sh5.clone())),
        );
        eval.add_constraint(
            is_sra.clone()
                * (srl[1].clone()
                    - qt[1].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[2].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - qt[3].clone() * (E::F::one() - sh4.clone()) * sh5.clone()),
        );
        eval.add_constraint(
            is_sra.clone()
                * (srl[0].clone()
                    - qt[0].clone() * (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone())
                    - qt[1].clone() * sh4.clone() * (E::F::one() - sh5.clone())
                    - qt[2].clone() * (E::F::one() - sh4.clone()) * sh5.clone()
                    - qt[3].clone() * sh4.clone() * sh5.clone()),
        );

        // Computing complement exp of exponent exp1_3 s.t. exp・exp1_3=2^8
        // is_sra・ (2・(2-sh1)・(4-3・sh2)・(16-15・sh3) - exp) = 0
        eval.add_constraint(
            is_sra.clone()
                * (E::F::from(2.into())
                    * (E::F::from(2.into()) - sh1.clone())
                    * (E::F::from(4.into()) - E::F::from(3.into()) * sh2.clone())
                    * (E::F::from(16.into()) - E::F::from(15.into()) * sh3.clone())
                    - exp.clone()),
        );

        // Replicating sign bit into vacated positions during logical right shift
        // is_sra・ (a_val_4 - (1-sh4)・(1-sh5)・(srl_4 + sgn・(exp1_3-1)・exp) - (sh4+sh5-sh4・sh5)・sgn・(2^8-1)) = 0
        // is_sra・ (a_val_3 - (1-sh4)・(1-sh5)・(srl_3) - (sh4)・(1-sh5)・(srl_3 + sgn・(exp1_3-1)・exp) - (sh5)・sgn・(2^8-1)) = 0
        // is_sra・ (a_val_2 -(1-sh5)・(srl_2) -(1-sh4)・(sh5)・(srl_2 + sgn・(exp1_3-1)・exp) - (sh4・sh5)・sgn・(2^8-1)) = 0
        // is_sra・ (a_val_1 - (1-sh4・sh5)・(srl_1) - (sh4)・(sh5)・(srl_1 + sgn・(exp1_3-1)・exp)) = 0

        eval.add_constraint(
            is_sra.clone()
                * (value_a[3].clone()
                    - (E::F::one() - sh4.clone())
                        * (E::F::one() - sh5.clone())
                        * (srl[3].clone()
                            + sgn_b.clone() * (exp1_3.clone() - E::F::one()) * exp.clone())
                    - (sh4.clone() + sh5.clone() - sh4.clone() * sh5.clone())
                        * sgn_b.clone()
                        * E::F::from(255.into())),
        );

        eval.add_constraint(
            is_sra.clone()
                * (value_a[2].clone()
                    - (E::F::one() - sh4.clone()) * (E::F::one() - sh5.clone()) * srl[2].clone()
                    - sh4.clone()
                        * (E::F::one() - sh5.clone())
                        * (srl[2].clone()
                            + sgn_b.clone() * (exp1_3.clone() - E::F::one()) * exp.clone())
                    - sh5.clone() * sgn_b.clone() * E::F::from(255.into())),
        );

        eval.add_constraint(
            is_sra.clone()
                * (value_a[1].clone()
                    - (E::F::one() - sh5.clone()) * srl[1].clone()
                    - (E::F::one() - sh4.clone())
                        * sh5.clone()
                        * (srl[1].clone()
                            + sgn_b.clone() * (exp1_3.clone() - E::F::one()) * exp.clone())
                    - sh4.clone() * sh5.clone() * sgn_b.clone() * E::F::from(255.into())),
        );

        eval.add_constraint(
            is_sra.clone()
                * (value_a[0].clone()
                    - (E::F::one() - sh4.clone() * sh5.clone()) * srl[0].clone()
                    - sh4.clone()
                        * sh5.clone()
                        * (srl[0].clone()
                            + sgn_b.clone() * (exp1_3.clone() - E::F::one()) * exp.clone())),
        );

        // Range checks for remainder values rem{1,2,3,4}
        // is_sra・(exp1_3 - 1 - rem1 - rem1_diff) = 0
        // is_sra・(exp1_3 - 1 - rem2 - rem2_diff) = 0
        // is_sra・(exp1_3 - 1 - rem3 - rem3_diff) = 0
        // is_sra・(exp1_3 - 1 - rem4 - rem4_diff) = 0
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_sra.clone()
                    * (exp1_3.clone() - E::F::one() - rem[i].clone() - rem_diff[i].clone()),
            );
        }
        // TODO: range-check h2
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, ProgramMemCheckChip, Range8Chip, RegisterMemCheckChip, SllChip,
            SubChip, TypeRChip,
        },
        test_utils::assert_chip,
        trace::{program::iter_program_steps, program_trace::ProgramTraces, PreprocessedTraces},
    };

    use super::*;
    use nexus_vm::{
        emulator::{Emulator, HarvardEmulator},
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Testing SRA (Shift Right Arithmetic) instruction
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 4),
            // Set x9 = 0x80000000 (most significant bit set, representing -2^31)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 9, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 9, 9, 31),
            // x10 = x9 >> 1 using SRA (should be 0xC0000000, preserving sign)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 10, 9, 1),
            // x11 = x9 >> 4 using SRA (should be 0xF8000000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 11, 9, 4),
            // Set x12 = -20 (testing negative numbers with SRA)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 12, 0, 20),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 12, 0, 12),
            // x13 = x12 >> 2 using SRA (-20 >> 2 = -5)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRA), 13, 12, 2),
            // Testing SRAI (Shift Right Arithmetic Immediate)
            // x14 = x9 >> 16 using SRAI (should be 0xFFFF8000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 14, 9, 16),
            // Set x15 = 0x7FFFFFFF (maximum positive 32-bit integer)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 15, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 15, 15, 31),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SUB), 15, 15, 1),
            // x16 = x15 >> 1 using SRAI (should be 0x3FFFFFFF)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 16, 15, 1),
            // x17 = x15 >> 31 using SRAI (should be 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SRAI), 17, 15, 31),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_sra_instructions() {
        type Chips = (
            CpuChip,
            TypeRChip,
            SubChip,
            AddChip,
            SraChip,
            SllChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            Range8Chip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let vm_traces = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let emulator = HarvardEmulator::from_basic_blocks(&basic_block);
        let program_memory = emulator.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTraces::new(LOG_SIZE, program_memory);
        let mut side_note = SideNote::new(&program_traces, emulator.get_public_input());

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &program_traces,
                &mut side_note,
            );
        }
        assert_chip::<Chips>(traces, None, Some(program_traces));
    }
}
