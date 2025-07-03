use std::marker::PhantomData;

use num_traits::{One, Zero};
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
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::ProgramStep,
    trace_eval,
};

use crate::{
    components::{
        execution::decoding::{instruction_decoding_trace, VirtualDecodingColumn},
        utils::{add_16bit_with_carry, add_with_carries, u32_to_16bit_parts_le},
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRamLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod sb;
mod sh;
mod sw;

mod decoding;

mod columns;
use columns::{Column, PreprocessedColumn};

pub trait StoreOp {
    const RAM2_ACCESSED: bool;
    const RAM3_4ACCESSED: bool;
    const OPCODE: BuiltinOpcode;

    /// Required alignment (in bytes) for the memory access.
    ///
    /// Zero indicates no alignment - used by SB.
    const ALIGNMENT: u8;
}

pub struct Store<S> {
    _phantom: PhantomData<S>,
}

impl<S: StoreOp> Store<S> {
    const RAM1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const RAM_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const REG1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rs1 is read
    const REG2_ACCESSED: BaseField = BaseField::from_u32_unchecked(0); // rs2 is unused

    const REG3_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rd is read
    const REG3_WRITE: BaseField = BaseField::from_u32_unchecked(0);

    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn iter_program_steps<'a>(
        &self,
        side_note: &SideNote<'a>,
    ) -> impl Iterator<Item = ProgramStep<'a>> {
        let store_opcode = S::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                opcode if opcode == Some(store_opcode),
            )
        })
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(S::OPCODE));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let (h_ram_base_addr, h_carry) = add_with_carries(value_a, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_a, Column::AVal);
        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);

        trace.fill_columns(row_idx, h_ram_base_addr, Column::HRamBaseAddr);
        trace.fill_columns(row_idx, [h_carry[1], h_carry[3]], Column::HCarry);

        self.generate_decoding_trace_row(trace, row_idx, program_step);

        if S::ALIGNMENT > 0 {
            assert!(h_ram_base_addr[0].is_multiple_of(S::ALIGNMENT));
            let h_ram_base_addr_aux = &mut trace.cols[Column::COLUMNS_NUM][row_idx];
            *h_ram_base_addr_aux = BaseField::from((h_ram_base_addr[0] / S::ALIGNMENT) as u32);
        }
    }
}

impl<S: StoreOp> BuiltInComponent for Store<S> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToRamLookupElements,
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
        let num_store_steps = self.iter_program_steps(side_note).count();
        let log_size = num_store_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        if S::ALIGNMENT > 0 {
            // manually add h-ram-base-addr-aux column
            trace.cols.push(vec![BaseField::zero(); 1 << log_size]);
        }

        for (row_idx, program_step) in self.iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut trace, row_idx, program_step);
        }
        // fill padding
        for row_idx in num_store_steps..1 << log_size {
            trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        trace.finalize()
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
        let expected_trace_len = if S::ALIGNMENT > 0 {
            Column::COLUMNS_NUM + 1
        } else {
            Column::COLUMNS_NUM
        };
        assert_eq!(component_trace.original_trace.len(), expected_trace_len);

        let (rel_inst_to_ram, rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);
        let pc = original_base_column!(component_trace, Column::Pc);
        let clk_next = original_base_column!(component_trace, Column::ClkNext);
        let pc_next = original_base_column!(component_trace, Column::PcNext);

        let h_ram_base_addr = original_base_column!(component_trace, Column::HRamBaseAddr);

        let a_val = original_base_column!(component_trace, Column::AVal);
        let b_val = original_base_column!(component_trace, Column::BVal);
        let c_val = original_base_column!(component_trace, Column::CVal);

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
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b, op_c],
                &a_val,
                &b_val,
                &c_val,
                &[
                    Self::REG1_ACCESSED.into(),
                    Self::REG2_ACCESSED.into(),
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
                ],
            ]
            .concat(),
        );
        let ram2_accessed = BaseField::from(S::RAM2_ACCESSED as u32);
        let ram3_4accessed = BaseField::from(S::RAM3_4ACCESSED as u32);
        // unused ram is zeroed for memory checking
        let mut ram_values = match S::ALIGNMENT as usize {
            0 => vec![b_val[0].clone()],
            n => b_val[..n].into(),
        };
        ram_values.resize(WORD_SIZE, BaseField::zero().into());
        ram_values.resize(WORD_SIZE, BaseField::zero().into());
        // provide(
        //     rel-inst-to-ram,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         h-ram-base-addr,
        //         ram1-val, ram2-val, ram3-val, ram4-val,
        //         ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
        //         ram-write
        //     )
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_ram,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &h_ram_base_addr,
                &ram_values,
                &[
                    Self::RAM1_ACCESSED.into(),
                    ram2_accessed.into(),
                    ram3_4accessed.into(),
                    Self::RAM_WRITE.into(),
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

        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let h_carry = trace_eval!(trace_eval, Column::HCarry);

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

        // (1 − is-local-pad) *
        // (h_ram_base_addr(1) + h_ram_base_addr(2) * 2^8 − a-val(1) − a-val(2) * 2^8 − c-val(1) − c-val(2) * 2^8 + h_carry(1) * 2^16) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[0].clone()
                    + h_ram_base_addr[1].clone() * BaseField::from(1 << 8)
                    - a_val[0].clone()
                    - a_val[1].clone() * BaseField::from(1 << 8)
                    - c_val[0].clone()
                    - c_val[1].clone() * BaseField::from(1 << 8)
                    + h_carry[0].clone() * BaseField::from(1 << 16)),
        );
        // (1 − is-local-pad) *
        // (h_ram_base_addr(3) + h_ram_base_addr(4) * 2^8 − a-val(3) − a-val(4) * 2^8 − c-val(3) − c-val(4) * 2^8 + h_carry(2) * 2^16) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[2].clone()
                    + h_ram_base_addr[3].clone() * BaseField::from(1 << 8)
                    - a_val[2].clone()
                    - a_val[3].clone() * BaseField::from(1 << 8)
                    - c_val[2].clone()
                    - c_val[3].clone() * BaseField::from(1 << 8)
                    + h_carry[1].clone() * BaseField::from(1 << 16)),
        );

        // h-carry(i) · (1 − h-carry(i)) = 0 for i = 1, 2
        for h_carry in h_carry {
            eval.add_constraint(h_carry.clone() * (E::F::one() - h_carry.clone()));
        }

        if S::ALIGNMENT > 0 {
            let h_ram_base_addr_aux = eval.next_trace_mask();
            // (1 − is-local-pad) · (ALIGNMENT · h-ram-base-addr-aux − h-ram-base-addr(1)) = 0
            eval.add_constraint(
                (E::F::one() - is_local_pad.clone())
                    * (h_ram_base_addr_aux.clone() * BaseField::from(S::ALIGNMENT as u32)
                        - h_ram_base_addr[0].clone()),
            );
        }

        Self::constrain_decoding(eval, &trace_eval);

        let (rel_inst_to_ram, rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            lookup_elements;

        let instr_val =
            columns::InstrVal::new(S::OPCODE.raw(), S::OPCODE.fn3().value()).eval(&trace_eval);
        let op_a = columns::OP_A.eval(&trace_eval);
        let op_b = columns::OP_B.eval(&trace_eval);
        let op_c = columns::OP_C.eval(&trace_eval);

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
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b, op_c],
                &a_val,
                &b_val,
                &c_val,
                &[
                    Self::REG1_ACCESSED.into(),
                    Self::REG2_ACCESSED.into(),
                    Self::REG3_ACCESSED.into(),
                    Self::REG3_WRITE.into(),
                ],
            ]
            .concat(),
        ));

        let ram2_accessed = E::F::from(BaseField::from(S::RAM2_ACCESSED as u32));
        let ram3_4accessed = E::F::from(BaseField::from(S::RAM3_4ACCESSED as u32));
        // unused ram is zeroed for memory checking
        let mut ram_values = match S::ALIGNMENT as usize {
            0 => vec![b_val[0].clone()],
            n => b_val[..n].into(),
        };
        ram_values.resize(WORD_SIZE, BaseField::zero().into());
        // provide(
        //     rel-inst-to-ram,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         h-ram-base-addr,
        //         ram1-val, ram2-val, ram3-val, ram4-val,
        //         ram1-accessed, ram2-accessed, ram3-accessed, ram4-accessed,
        //         ram-write
        //     )
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_ram,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &h_ram_base_addr,
                &ram_values,
                &[
                    Self::RAM1_ACCESSED.into(),
                    ram2_accessed,
                    ram3_4accessed,
                    Self::RAM_WRITE.into(),
                ],
            ]
            .concat(),
        ));

        eval.finalize_logup_in_pairs();
    }
}

pub const SB: Store<sb::Sb> = Store::new();
pub const SH: Store<sh::Sh> = Store::new();
pub const SW: Store<sw::Sw> = Store::new();

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    use crate::{
        components::{
            execution::load::tests::setup_ir, Cpu, CpuBoundary, ProgramMemory,
            ProgramMemoryBoundary, ReadWriteMemory, ReadWriteMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADD, ADDI,
        },
        framework::{
            test_utils::{assert_component, components_claimed_sum, AssertContext},
            MachineComponent,
        },
    };

    const BASE_TEST_COMPONENTS: &[&dyn MachineComponent] = &[
        &Cpu,
        &CpuBoundary,
        &RegisterMemory,
        &RegisterMemoryBoundary,
        &ProgramMemory,
        &ProgramMemoryBoundary,
        &ReadWriteMemory,
        &ReadWriteMemoryBoundary,
        &ADD,
        &ADDI,
    ];

    fn assert_store_constraints<C>(component: C, opcode: BuiltinOpcode)
    where
        C: BuiltInComponent + 'static + Sync,
        C::LookupElements: 'static + Sync,
    {
        let mut instr = setup_ir();
        // x2 should be 0x81008
        instr.push(Instruction::new_ir(Opcode::from(opcode), 2, 2, 0));
        let (view, program_trace) =
            k_trace_direct(&vec![BasicBlock::new(instr)], 1).expect("error generating trace");
        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = assert_component(component, assert_ctx);
        claimed_sum += components_claimed_sum(BASE_TEST_COMPONENTS, assert_ctx);
        assert!(claimed_sum.is_zero());
    }

    #[test]
    fn assert_sb_constraints() {
        assert_store_constraints(SB, BuiltinOpcode::SB);
    }

    #[test]
    fn assert_sh_constraints() {
        assert_store_constraints(SH, BuiltinOpcode::SH);
    }

    #[test]
    fn assert_sw_constraints() {
        assert_store_constraints(SW, BuiltinOpcode::SW);
    }
}
