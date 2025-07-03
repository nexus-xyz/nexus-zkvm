use std::marker::PhantomData;

use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::{ProgramStep, Word},
    trace_eval,
};

use crate::{
    components::execution::decoding::{instruction_decoding_trace, VirtualDecodingColumn},
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, BitwiseInstrLookupElements, ComponentLookupElements,
        InstToProgMemoryLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
mod trace;

mod and;
mod or;
mod xor;

use columns::{Column, PreprocessedColumn, A_VAL_LOW, B_VAL_LOW, C_VAL_LOW};
pub use trace::BitwiseAccumulator;

pub const AND_LOOKUP_IDX: u32 = 1;
pub const OR_LOOKUP_IDX: u32 = 2;
pub const XOR_LOOKUP_IDX: u32 = 3;

pub trait BitwiseOp {
    const OPCODE: BuiltinOpcode;
    const REG2_ACCESSED: bool;
    const BITWISE_LOOKUP_IDX: u32;

    /// Columns used for instruction decoding.
    type LocalColumn: AirColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
    );

    fn constrain_decoding<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    );

    /// Returns a linear combinations of decoding columns that represent [op-a, op-b, op-c]
    ///
    /// op-c is an immediate in case of Type-I instructions.
    fn combine_reg_addresses<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; 3];

    /// Returns a linear combination of decoding columns that represent raw instruction word.
    fn combine_instr_val<E: EvalAtRow>(
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
    ) -> [E::F; WORD_SIZE];
}

pub struct Bitwise<B> {
    _phantom: PhantomData<B>,
}

struct ExecutionResult {
    out_bytes: Word,
    value_a_4_7: Word,
    value_b_0_3: Word,
    value_b_4_7: Word,
    value_c_0_3: Word,
    value_c_4_7: Word,
}

impl<B: BitwiseOp> Bitwise<B> {
    const REG1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rs1 is read
    const REG3_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rd is written
    const REG3_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn iter_program_steps<'a>(
        &self,
        side_note: &SideNote<'a>,
    ) -> impl Iterator<Item = ProgramStep<'a>> {
        let bitwise_opcode = B::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                opcode if opcode == Some(bitwise_opcode),
            )
        })
    }
}

impl<B: BitwiseOp> BuiltInComponent for Bitwise<B> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
        BitwiseInstrLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = self.iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut accum = BitwiseAccumulator::default();

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in self.iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut common_trace, row_idx, program_step, &mut accum);
            B::generate_trace_row(row_idx, &mut local_trace, program_step);
        }

        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        // store computed multiplicities
        let accum_mut = match B::BITWISE_LOOKUP_IDX {
            idx if idx == AND_LOOKUP_IDX => &mut side_note.bitwise.bitwise_accum_and,
            idx if idx == OR_LOOKUP_IDX => &mut side_note.bitwise.bitwise_accum_or,
            idx if idx == XOR_LOOKUP_IDX => &mut side_note.bitwise.bitwise_accum_xor,
            _ => panic!("invalid lookup idx"),
        };
        for (row, mult) in accum.accum.iter() {
            *accum_mut.accum.entry(*row).or_default() += mult;
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
        let (
            rel_inst_to_prog_memory,
            rel_cont_prog_exec,
            rel_inst_to_reg_memory,
            rel_bitwise_instr,
        ) = Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);
        let pc = original_base_column!(component_trace, Column::Pc);
        let a_val = original_base_column!(component_trace, Column::AVal);
        let b_val = original_base_column!(component_trace, Column::BVal);
        let c_val = original_base_column!(component_trace, Column::CVal);

        let clk_next = original_base_column!(component_trace, Column::ClkNext);
        let pc_next = original_base_column!(component_trace, Column::PcNext);

        let a_val_high = original_base_column!(component_trace, Column::AValHigh);
        let a_val_low = A_VAL_LOW.combine_from_finalized_trace(&component_trace);

        let b_val_high = original_base_column!(component_trace, Column::BValHigh);
        let b_val_low = B_VAL_LOW.combine_from_finalized_trace(&component_trace);

        let c_val_high = original_base_column!(component_trace, Column::CValHigh);
        let c_val_low = C_VAL_LOW.combine_from_finalized_trace(&component_trace);

        let bitwise_lookup_idx = BaseField::from(B::BITWISE_LOOKUP_IDX);
        for i in 0..WORD_SIZE {
            logup_trace_builder.add_to_relation_with(
                &rel_bitwise_instr,
                [is_local_pad.clone()],
                |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
                &[
                    bitwise_lookup_idx.into(),
                    b_val_low[i].clone(),
                    c_val_low[i].clone(),
                    a_val_low[i].clone(),
                ],
            );

            logup_trace_builder.add_to_relation_with(
                &rel_bitwise_instr,
                [is_local_pad.clone()],
                |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
                &[
                    bitwise_lookup_idx.into(),
                    b_val_high[i].clone(),
                    c_val_high[i].clone(),
                    a_val_high[i].clone(),
                ],
            );
        }

        let decoding_trace = instruction_decoding_trace(
            component_trace.log_size(),
            self.iter_program_steps(side_note),
        );
        let instr_val = original_base_column!(decoding_trace, VirtualDecodingColumn::InstrVal);

        let [op_a] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpA);
        let [op_b] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpB);
        let [op_c] = original_base_column!(decoding_trace, VirtualDecodingColumn::OpC);

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
        let reg2_accessed = BaseField::from(B::REG2_ACCESSED as u32);
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
                    Self::REG1_ACCESSED.into(),
                    reg2_accessed.into(),
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
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
        let [clk_carry] = trace_eval!(trace_eval, Column::ClkCarry);
        let [pc_carry] = trace_eval!(trace_eval, Column::PcCarry);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = trace_eval!(trace_eval, Column::ClkNext);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        // (1 − is-local-pad) · (clk-next(1) + clk-next(2) · 2^8 + clk-carry(1) · 2^16 − clk(1) − clk(2) · 2^8 − 1) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[0].clone() + clk_carry.clone() * BaseField::from(1 << 16)
                    - clk[0].clone()
                    - E::F::one()),
        );
        // (1 − is-local-pad) · (clk-next(3) + clk-next(4) · 2^8 + clk-carry(2) · 2^16 − clk(3) − clk(4) · 2^8 − clk-carry(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[1].clone() - clk[1].clone() - clk_carry.clone()),
        );

        // (clk-carry) · (1 − clk-carry) = 0
        eval.add_constraint(clk_carry.clone() * (E::F::one() - clk_carry.clone()));

        // (1 − is-local-pad) · (pc-next(1) + pc-next(2) · 2^8 + pc-carry(1) · 2^16 − pc(1) − pc(2) · 2^8 − 4) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[0].clone() + pc_carry.clone() * BaseField::from(1 << 16)
                    - pc[0].clone()
                    - E::F::from(4.into())),
        );
        // (1 − is-local-pad) · (pc-next(3) + pc-next(4) · 2^8 + pc-carry(2) · 2^16 − pc(3) − pc(4) · 2^8 − pc-carry(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[1].clone() - pc[1].clone() - pc_carry.clone()),
        );
        // (pc-carry) · (1 − pc-carry) = 0
        eval.add_constraint(pc_carry.clone() * (E::F::one() - pc_carry.clone()));

        let a_val_high = trace_eval!(trace_eval, Column::AValHigh);
        let a_val_low = A_VAL_LOW.eval(&trace_eval);

        let b_val_high = trace_eval!(trace_eval, Column::BValHigh);
        let b_val_low = B_VAL_LOW.eval(&trace_eval);

        let c_val_high = trace_eval!(trace_eval, Column::CValHigh);
        let c_val_low = C_VAL_LOW.eval(&trace_eval);

        let local_trace_eval = TraceEval::new(eval);
        B::constrain_decoding(eval, &trace_eval, &local_trace_eval);

        // logup interactions
        let (
            rel_inst_to_prog_memory,
            rel_cont_prog_exec,
            rel_inst_to_reg_memory,
            rel_bitwise_instr,
        ) = lookup_elements;

        let bitwise_lookup_idx: E::F = BaseField::from(B::BITWISE_LOOKUP_IDX).into();
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                rel_bitwise_instr,
                (E::F::one() - is_local_pad.clone()).into(),
                &[
                    bitwise_lookup_idx.clone(),
                    b_val_low[i].clone(),
                    c_val_low[i].clone(),
                    a_val_low[i].clone(),
                ],
            ));

            eval.add_to_relation(RelationEntry::new(
                rel_bitwise_instr,
                (E::F::one() - is_local_pad.clone()).into(),
                &[
                    bitwise_lookup_idx.clone(),
                    b_val_high[i].clone(),
                    c_val_high[i].clone(),
                    a_val_high[i].clone(),
                ],
            ));
        }

        let instr_val = B::combine_instr_val(&local_trace_eval);
        let reg_addrs = B::combine_reg_addresses(&local_trace_eval);

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
                pc_next[0].clone(),
                pc_next[1].clone(),
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
        let reg2_accessed: E::F = BaseField::from(B::REG2_ACCESSED as u32).into();
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &reg_addrs,
                &a_val,
                &b_val,
                &c_val,
                &[
                    Self::REG1_ACCESSED.into(),
                    reg2_accessed,
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
                ],
            ]
            .concat(),
        ));

        eval.finalize_logup_in_pairs();
    }
}

pub const AND: Bitwise<and::And> = Bitwise::new();
pub const ANDI: Bitwise<and::AndI> = Bitwise::new();
pub const OR: Bitwise<or::Or> = Bitwise::new();
pub const ORI: Bitwise<or::OrI> = Bitwise::new();
pub const XOR: Bitwise<xor::Xor> = Bitwise::new();
pub const XORI: Bitwise<xor::XorI> = Bitwise::new();

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            BitwiseMultiplicity, Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary,
            RegisterMemory, RegisterMemoryBoundary, ADD, ADDI,
        },
        framework::{
            test_utils::{assert_component, components_claimed_sum, AssertContext},
            MachineComponent,
        },
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    const BASE_TEST_COMPONENTS: &[&dyn MachineComponent] = &[
        &Cpu,
        &CpuBoundary,
        &RegisterMemory,
        &RegisterMemoryBoundary,
        &ProgramMemory,
        &ProgramMemoryBoundary,
        &ADD,
        &ADDI,
    ];

    fn assert_components<C1, C2>(c1: C1, c2: C2, instr: &[Instruction])
    where
        C1: BuiltInComponent + 'static + Sync,
        C1::LookupElements: 'static + Sync,
        C2: BuiltInComponent + 'static + Sync,
        C2::LookupElements: 'static + Sync,
    {
        let basic_block = vec![BasicBlock::new(instr.to_vec())];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(c1, assert_ctx);
        claimed_sum += assert_component(c2, assert_ctx);

        claimed_sum += components_claimed_sum(BASE_TEST_COMPONENTS, assert_ctx);
        claimed_sum += assert_component(BitwiseMultiplicity, assert_ctx);

        assert!(claimed_sum.is_zero());
    }

    #[test]
    fn assert_and_constraints() {
        assert_components(
            AND,
            ANDI,
            &[
                // 0b11100 & 0b01000 = 0b01000
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 28), // x1 = 0b11100
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 8),  // x2 = 0b01000
                Instruction::new_ir(Opcode::from(BuiltinOpcode::AND), 3, 1, 2),   // x3 = x1 & x2
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ANDI), 3, 1, 8), // x3 = x1 & 0b01000
            ],
        );
    }

    #[test]
    fn assert_or_constraints() {
        assert_components(
            OR,
            ORI,
            &[
                // 0b10010 | 0b01100 = 0b11110
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 18), // x1 = 0b10010
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 12), // x2 = 0b01100
                Instruction::new_ir(Opcode::from(BuiltinOpcode::OR), 3, 1, 2),    // x3 = x1 | x2
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ORI), 3, 1, 12), // x3 = x1 | 0b01100
            ],
        );
    }

    #[test]
    fn assert_xor_constraints() {
        assert_components(
            XOR,
            XORI,
            &[
                // 0b11011 ^ 0b10101 = 0b01110
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 27), // x1 = 0b11011
                Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 2, 0, 21), // x2 = 0b10101
                Instruction::new_ir(Opcode::from(BuiltinOpcode::XOR), 3, 1, 2),   // x3 = x1 ^ x2
                Instruction::new_ir(Opcode::from(BuiltinOpcode::XORI), 3, 1, 21), // x3 = x1 ^ 0b10101
            ],
        );
    }
}
