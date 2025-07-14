use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::{ProgramStep, Word},
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::decoding::{
            type_i::{self, TypeIDecoding},
            ComponentDecodingTrace, DecodingColumn, InstructionDecoding,
        },
        utils::{
            add_16bit_with_carry, add_with_carries, constraints::ClkIncrement,
            u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub const JALR: Jalr = Jalr;

pub struct Jalr;

struct JalrDecoding;
impl TypeIDecoding for JalrDecoding {
    const OPCODE: BuiltinOpcode = Jalr::OPCODE;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;
    const C_VAL: Self::MainColumn = Column::CVal;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

type Decoding = type_i::TypeI<JalrDecoding>;

struct ExecutionResult {
    qt_aux: u8,
    rem_aux: bool,
    pc_carry_bits: [bool; 3], // At 16-bit boundaries
    carry_bits: [bool; 2],    // At 16-bit boundaries
    a_val: Word,
}

impl Jalr {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::JALR;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;

    fn iter_program_steps<'a>(side_note: &'a SideNote) -> impl Iterator<Item = ProgramStep<'a>> {
        let opcode = Self::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                step_opcode if step_opcode == Some(opcode),
            )
        })
    }

    fn execute_step(program_step: ProgramStep) -> ExecutionResult {
        let value_b = program_step.get_value_b();
        let imm = program_step.get_value_c().0;
        let pc = program_step.step.pc.to_le_bytes();

        let (pc_next, pc_carry_bits) = add_with_carries(value_b, imm);

        let rem_aux = pc_next[0] & 0x1 == 1;
        // To ensure 2*qt_aux = pc_next
        let qt_aux = pc_next[0] >> 1;

        let (a_val, carry_bits) = add_with_carries(pc, 4u32.to_le_bytes());

        let pc_carry_bits = [pc_carry_bits[0], pc_carry_bits[1], pc_carry_bits[3]];
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            qt_aux,
            rem_aux,
            pc_carry_bits,
            a_val,
            carry_bits,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let pc_next = step.next_pc;
        let pc_next_parts = u32_to_16bit_parts_le(pc_next);
        let pc_next_bytes = pc_next.to_le_bytes();

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let ExecutionResult {
            qt_aux,
            rem_aux,
            pc_carry_bits,
            carry_bits,
            a_val,
        } = Self::execute_step(program_step);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);

        trace.fill_columns(row_idx, pc_next_bytes[1], Column::PcNext8_15);
        trace.fill_columns(row_idx, [pc_next_parts[1]], Column::PcNextHigh);
        trace.fill_columns(row_idx, pc_carry_bits, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, value_b, Column::BVal);
        trace.fill_columns(row_idx, value_c, Column::CVal);

        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
        trace.fill_columns(row_idx, qt_aux, Column::PcQtAux);
        trace.fill_columns(row_idx, rem_aux, Column::PcRemAux);
    }

    /// Computes pc-next 16-bit parts for the interaction trace.
    fn generate_pc_next_columns<'a>(
        decoding_trace: &'a ComponentDecodingTrace,
    ) -> [FinalizedColumn<'a>; WORD_SIZE_HALVED] {
        let pad_len = (1usize << decoding_trace.log_size) - decoding_trace.program_steps.len();
        let pc_next: Vec<[u16; WORD_SIZE_HALVED]> = decoding_trace
            .program_steps
            .iter()
            .map(|program_step| u32_to_16bit_parts_le(program_step.step.next_pc))
            .collect();

        std::array::from_fn(|i| {
            let col_iter = pc_next
                .iter()
                .map(|b| b[i] as u32)
                .chain(std::iter::repeat_n(0, pad_len));
            let col = BaseColumn::from_iter(col_iter.map(BaseField::from));
            FinalizedColumn::new_virtual(col)
        })
    }
}

impl BuiltInComponent for Jalr {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_add_steps = Self::iter_program_steps(side_note).count();
        let log_size = num_add_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in Self::iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
            Decoding::generate_trace_row(row_idx, &mut local_trace, program_step);
        }
        // fill padding
        for row_idx in num_add_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(local_trace.finalize())
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        assert_eq!(
            component_trace.original_trace.len(),
            Column::COLUMNS_NUM + type_i::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        // jalr doesn't have pc_next column in its trace, execution component trait is not usable because of this
        //
        // generate logups manually

        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);
        let clk = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(Column::Clk);
        let clk_next =
            component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(Column::ClkNext);

        let pc = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(Column::Pc);

        let decoding_trace = ComponentDecodingTrace::new(
            component_trace.log_size(),
            Self::iter_program_steps(side_note),
        );
        let instr_val = decoding_trace.base_column::<{ WORD_SIZE }>(DecodingColumn::InstrVal);

        let [op_a] = decoding_trace.base_column(DecodingColumn::OpA);
        let a_val = decoding_trace.a_val();

        let zeroed_reg = [0u32; WORD_SIZE].map(|byte| BaseField::from(byte).into());
        let op_b = decoding_trace.op_b();
        let b_val = component_trace.original_base_column::<{ WORD_SIZE }, _>(Column::BVal);
        let (op_c, c_val) = (BaseField::zero().into(), zeroed_reg);

        let pc_next = Self::generate_pc_next_columns(&decoding_trace);

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_prog_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        );
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[clk_next, pc_next].concat(),
        );
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b, op_c],
                &a_val,
                &b_val,
                &c_val,
                &[
                    BaseField::from(Self::REG1_ACCESSED as u32).into(),
                    BaseField::from(Self::REG2_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_WRITE as u32).into(),
                ],
            ]
            .concat(),
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = trace_eval!(trace_eval, Column::ClkNext);

        ClkIncrement {
            is_local_pad: Column::IsLocalPad,
            clk: Column::Clk,
            clk_next: Column::ClkNext,
            clk_carry: Column::ClkCarry,
        }
        .constrain(eval, &trace_eval);

        let pc = trace_eval!(trace_eval, Column::Pc);

        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);
        // add two bytes at a time
        //
        // (1 − is-local-pad) · (pc(1) + 4 − a-val(1) − h-carry(1) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(2) + h-carry(1) − a-val(2) − h-carry(2) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (E::F::from(4.into()) + pc[0].clone()
                    - h_carry_1.clone() * BaseField::from(1 << 8).pow(2)
                    - a_val[0].clone()
                    - a_val[1].clone() * BaseField::from(1 << 8)),
        );
        // (1 − is-local-pad) · (pc(3) + h-carry(2) − a-val(3) − h-carry(3) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(4) + h-carry(3) − a-val(4) − h-carry(4) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc[1].clone() + h_carry_1.clone()
                    - h_carry_2.clone() * BaseField::from(1 << 8).pow(2)
                    - a_val[2].clone()
                    - a_val[3].clone() * BaseField::from(1 << 8)),
        );
        // (h-carry(1)) · (1 − h-carry(1) ) = 0
        // (h-carry(2)) · (1 − h-carry(2) ) = 0
        eval.add_constraint(h_carry_1.clone() * (E::F::one() - h_carry_1));
        eval.add_constraint(h_carry_2.clone() * (E::F::one() - h_carry_2));

        let [pc_rem_aux] = trace_eval!(trace_eval, Column::PcRemAux);
        let [pc_qt_aux] = trace_eval!(trace_eval, Column::PcQtAux);
        let [pc_next8_15] = trace_eval!(trace_eval, Column::PcNext8_15);
        let [pc_next_high] = trace_eval!(trace_eval, Column::PcNextHigh);

        let [pc_carry_1, pc_carry_2, pc_carry_4] = trace_eval!(trace_eval, Column::PcCarry);

        let pc_next_aux_1 = pc_rem_aux.clone() + pc_qt_aux.clone() * BaseField::from(1 << 1);
        // (1 − is-local-pad) · (b-val(1) + c-val(1) − pc-next-aux(1) − pc-carry(1) · 2^8) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (b_val[0].clone() + c_val[0].clone()
                    - pc_next_aux_1
                    - pc_carry_1.clone() * BaseField::from(1 << 8)),
        );
        // (1 − is-local-pad) · (b-val(2) + c-val(2) + pc-carry(1) − pc-next-aux(2) − pc-carry(2) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (b_val[1].clone() + c_val[1].clone() + pc_carry_1.clone()
                    - pc_next8_15.clone()
                    - pc_carry_2.clone() * BaseField::from(1 << 8)),
        );
        // add two bytes at a time for the second pair
        //
        // (1 − is-local-pad) · (b-val(3) + c-val(3) + pc-carry(2) − pc-next-aux(3) − pc-carry(3) · 2^8 ) = 0
        // (1 − is-local-pad) · (b-val(4) + c-val(4) + pc-carry(3) − pc-next-aux(4) − pc-carry(4) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (c_val[2].clone()
                    + c_val[3].clone() * BaseField::from(1 << 8)
                    + b_val[2].clone()
                    + b_val[3].clone() * BaseField::from(1 << 8)
                    + pc_carry_1.clone()
                    - pc_carry_4.clone() * BaseField::from(1 << 8).pow(2)
                    - pc_next_high.clone()),
        );

        // (pc-carry(1)) · (1 − pc-carry(1) ) = 0
        // (pc-carry(2)) · (1 − pc-carry(2) ) = 0
        // (pc-carry(4)) · (1 − pc-carry(4) ) = 0
        eval.add_constraint(pc_carry_1.clone() * (E::F::one() - pc_carry_1));
        eval.add_constraint(pc_carry_2.clone() * (E::F::one() - pc_carry_2));
        eval.add_constraint(pc_carry_4.clone() * (E::F::one() - pc_carry_4));
        // (pc-rem-aux) · (1 − pc-rem-aux) = 0
        eval.add_constraint(pc_rem_aux.clone() * (E::F::one() - pc_rem_aux));

        let pc_next_low = pc_qt_aux.clone() * BaseField::from(1 << 1)
            + pc_next8_15.clone() * BaseField::from(1 << 8);

        let decoding_trace_eval = TraceEval::new(eval);
        Decoding::constrain_decoding(eval, &trace_eval, &decoding_trace_eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;
        let reg_addrs = Decoding::combine_reg_addresses(&decoding_trace_eval);
        let instr_val = Decoding::combine_instr_val(&decoding_trace_eval);

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_prog_memory,
            (is_local_pad.clone() - E::F::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        ));
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        eval.add_to_relation(RelationEntry::new(
            rel_cont_prog_exec,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk_next[0].clone(),
                clk_next[1].clone(),
                pc_next_low,
                pc_next_high,
            ],
        ));
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &reg_addrs,
                &a_val,
                &b_val,
                &zero_array::<WORD_SIZE, E>(),
                &[
                    BaseField::from(Self::REG1_ACCESSED as u32).into(),
                    BaseField::from(Self::REG2_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_WRITE as u32).into(),
                ],
            ]
            .concat(),
        ));
        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADDI, LUI,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_common::constants::ELF_TEXT_START;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_jalr_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Initialize registers
            // Set x1 = ELF_TEXT_START + 16 (base address for first JALR)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 0, 0, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 1, ELF_TEXT_START + 16),
            // Set x2 = ELF_TEXT_START + 44 (base address for second JALR)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 0, 0, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 2, ELF_TEXT_START + 44),
            // Case 1: JALR with positive offset
            // JALR x3, x1, 4 (Jump to x1 + 4 and store return address in x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 3, 1, 12),
            // Instructions to skip
            Instruction::unimpl(),
            // Target of first JALR
            // ADDI x4, x0, 1 (Set x4 = 1 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 1),
            // Case 2: JALR with negative offset
            // JALR x5, x2, -8 (Jump to x2 - 8 and store return address in x5)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 5, 2, 0xFF8), // -8 in 12-bit two's complement
            // Instructions to skip
            Instruction::unimpl(),
            // Target of second JALR
            // ADDI x6, x0, 2 (Set x6 = 2 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 0, 2),
            // Case 3: JALR with x0 as destination (used for unconditional jumps without saving return address)
            // JALR x0, x1, 24 (Jump to x1 + 24 without saving return address)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::JALR), 0, 1, 32),
            // Instruction to skip
            Instruction::unimpl(),
            // Target of last JALR
            // ADDI x7, x0, 3 (Set x7 = 3 to indicate this instruction was reached)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 7, 0, 3),
        ])];

        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(JALR, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &ADDI,
                &LUI,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
