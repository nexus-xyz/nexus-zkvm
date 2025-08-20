use std::marker::PhantomData;

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::ProgramStep,
    trace_eval,
    utils::zero_array,
    virtual_column::VirtualColumn,
};

use crate::{
    components::{
        execution::common::{ExecutionComponent, ExecutionLookupEval},
        read_write_memory::ShiftedBaseAddr,
        utils::{
            add_16bit_with_carry, add_with_carries,
            constraints::{ClkIncrement, PcIncrement},
            u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRamLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements, RamWriteAddressLookupElements, RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod sb;
mod sh;
mod sw;

mod decoding;

mod columns;
use columns::{Column, PreprocessedColumn};
use decoding::Decoding;

pub trait StoreOp {
    const RAM2_ACCESSED: bool;
    const RAM3_4ACCESSED: bool;
    const OPCODE: BuiltinOpcode;

    /// Required alignment (in bytes) for the memory access.
    ///
    /// Zero indicates no alignment - used by SB.
    const ALIGNMENT: u8;

    /// Add constraints for memory alignment.
    fn constrain_alignment<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    );
    /// Add logup columns for the alignment range check.
    fn generate_interaction_trace(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    );
}

pub struct Store<T> {
    _phantom: PhantomData<T>,
}

impl<T: StoreOp> ExecutionComponent for Store<T> {
    const OPCODE: BuiltinOpcode = <T as StoreOp>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = false;
}

impl<T: StoreOp> Store<T> {
    const RAM1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const RAM_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let step = &program_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(T::OPCODE));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (_pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_a = program_step.get_value_a();
        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let (h_ram_base_addr, h_carry) = add_with_carries(value_a, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_a, Column::AVal);
        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);

        trace.fill_columns(row_idx, h_ram_base_addr, Column::HRamBaseAddr);
        trace.fill_columns(row_idx, [h_carry[1], h_carry[3]], Column::HCarry);

        Decoding::generate_decoding_trace_row(trace, row_idx, program_step, range_check_accum);

        if T::ALIGNMENT > 0 {
            assert!(h_ram_base_addr[0].is_multiple_of(T::ALIGNMENT));
            let h_ram_base_addr_aux = &mut trace.cols[Column::COLUMNS_NUM][row_idx];
            let addr_rem = h_ram_base_addr[0] / T::ALIGNMENT;
            *h_ram_base_addr_aux = BaseField::from(addr_rem as u32);

            match T::ALIGNMENT {
                2 => range_check_accum.range128.add_value(addr_rem),
                4 => range_check_accum.range64.add_value(addr_rem),
                _ => {}
            }
        }
    }
}

impl<T: StoreOp> BuiltInComponent for Store<T> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToRamLookupElements,
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
        RamWriteAddressLookupElements,
        RangeCheckLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_store_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_store_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        if T::ALIGNMENT > 0 {
            // manually add h-ram-base-addr-aux column
            trace.cols.push(vec![BaseField::zero(); 1 << log_size]);
        }
        let mut range_check_accum = RangeCheckAccumulator::default();

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut trace, row_idx, program_step, &mut range_check_accum);
        }
        side_note.range_check.append(range_check_accum);
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
        let expected_trace_len = if T::ALIGNMENT > 0 {
            Column::COLUMNS_NUM + 1
        } else {
            Column::COLUMNS_NUM
        };
        assert_eq!(component_trace.original_trace.len(), expected_trace_len);

        let (
            rel_inst_to_ram,
            rel_inst_to_prog_memory,
            rel_cont_prog_exec,
            rel_inst_to_reg_memory,
            rel_ram_write_addr,
            range_check,
        ) = Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);

        let h_ram_base_addr = original_base_column!(component_trace, Column::HRamBaseAddr);
        let b_val = original_base_column!(component_trace, Column::BVal);

        let ram2_accessed = BaseField::from(T::RAM2_ACCESSED as u32);
        let ram3_4accessed = BaseField::from(T::RAM3_4ACCESSED as u32);
        // unused ram is zeroed for memory checking
        let mut ram_values = match T::ALIGNMENT as usize {
            0 => vec![b_val[0].clone()],
            n => b_val[..n].into(),
        };
        ram_values.resize(WORD_SIZE, BaseField::zero().into());

        Self::generate_address_logup(
            &mut logup_trace_builder,
            &component_trace,
            &rel_ram_write_addr,
        );
        T::generate_interaction_trace(&mut logup_trace_builder, &component_trace, &range_check);

        Decoding::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            &range_check,
        );
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

        <Self as ExecutionComponent>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            side_note,
            &(
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            is_local_pad,
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let (
            rel_inst_to_ram,
            rel_inst_to_prog_memory,
            rel_cont_prog_exec,
            rel_inst_to_reg_memory,
            rel_ram_write_addr,
            range_check,
        ) = lookup_elements;
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = columns::CVal.eval(&trace_eval);

        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let h_carry = trace_eval!(trace_eval, Column::HCarry);

        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = ClkIncrement {
            clk: Column::Clk,
            clk_carry: Column::ClkCarry,
        }
        .eval(eval, &trace_eval);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = PcIncrement {
            pc: Column::Pc,
            pc_carry: Column::PcCarry,
        }
        .eval(eval, &trace_eval);

        // (1 − is-local-pad) · (
        //     h-ram-base-addr(1) + h-ram-base-addr(2) · 2^8
        //     − a-val(1) − a-val(2) · 2^8
        //     − c-val(1) − c-val(2) · 2^8
        //     + h-carry(1) · 2^16
        // ) = 0
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
        // (1 − is-local-pad) · (
        //     h-ram-base-addr(3) + h-ram-base-addr(4) · 2^8
        //     − h-carry(1)
        //     − a-val(3) − a-val(4) · 2^8
        //     − c-val(3) − c-val(4) · 2^8
        //     + h-carry(2) · 2^16
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[2].clone()
                    + h_ram_base_addr[3].clone() * BaseField::from(1 << 8)
                    - h_carry[0].clone()
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

        Self::constrain_address_write(eval, &trace_eval, rel_ram_write_addr);
        T::constrain_alignment(eval, &trace_eval, range_check);

        Decoding::constrain_decoding(eval, &trace_eval, range_check);

        let instr_val =
            columns::InstrVal::new(T::OPCODE.raw(), T::OPCODE.fn3().value()).eval(&trace_eval);
        let op_a = columns::OP_A.eval(&trace_eval);
        let op_b = columns::OP_B.eval(&trace_eval);
        let op_c = E::F::zero();

        let ram2_accessed = E::F::from(BaseField::from(T::RAM2_ACCESSED as u32));
        let ram3_4accessed = E::F::from(BaseField::from(T::RAM3_4ACCESSED as u32));
        // unused ram is zeroed for memory checking
        let mut ram_values = match T::ALIGNMENT as usize {
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

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            ExecutionLookupEval {
                is_local_pad,
                reg_addrs: [op_a, op_b, op_c],
                reg_values: [a_val, b_val, zero_array::<WORD_SIZE, E>()],
                instr_val,
                clk,
                clk_next,
                pc,
                pc_next,
            },
        );
        eval.finalize_logup_in_pairs();
    }
}

impl<T: StoreOp> Store<T> {
    fn constrain_address_write<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RamWriteAddressLookupElements,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let mut h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);
        let byte_0 = h_ram_base_addr[0].clone();

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (E::F::one() - is_local_pad.clone()).into(),
            &h_ram_base_addr,
        ));

        for (shift, accessed) in [T::RAM2_ACCESSED, T::RAM3_4ACCESSED, T::RAM3_4ACCESSED]
            .iter()
            .enumerate()
        {
            if !*accessed {
                return;
            }
            h_ram_base_addr[0] = byte_0.clone() + E::F::from(BaseField::from(shift as u32 + 1));
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                (E::F::one() - is_local_pad.clone()).into(),
                &h_ram_base_addr,
            ));
        }
    }

    fn generate_address_logup(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        lookup_elements: &RamWriteAddressLookupElements,
    ) {
        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let mut h_ram_base_addr = original_base_column!(component_trace, Column::HRamBaseAddr);

        logup_trace_builder.add_to_relation_with(
            lookup_elements,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &h_ram_base_addr,
        );
        for (shift, accessed) in [T::RAM2_ACCESSED, T::RAM3_4ACCESSED, T::RAM3_4ACCESSED]
            .iter()
            .enumerate()
        {
            if !*accessed {
                return;
            }
            let shifted_addr = ShiftedBaseAddr {
                column: Column::HRamBaseAddr,
                offset: shift as u32 + 1,
            };
            let byte_0 = shifted_addr.combine_from_finalized_trace(component_trace);
            h_ram_base_addr[0] = byte_0;

            logup_trace_builder.add_to_relation_with(
                lookup_elements,
                [is_local_pad.clone()],
                |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
                &h_ram_base_addr,
            );
        }
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

    use crate::{
        components::{
            execution::load::tests::setup_ir, Cpu, CpuBoundary, PrivateMemoryBoundary,
            ProgramMemory, ProgramMemoryBoundary, ReadWriteMemory, RegisterMemory,
            RegisterMemoryBoundary, ADD, ADDI, RANGE128, RANGE16, RANGE256, RANGE64, RANGE8,
        },
        framework::{
            test_utils::{assert_component, components_claimed_sum, AssertContext},
            MachineComponent,
        },
        verify::verify_logup_sum,
    };

    const BASE_TEST_COMPONENTS: &[&dyn MachineComponent] = &[
        &Cpu,
        &CpuBoundary,
        &RegisterMemory,
        &RegisterMemoryBoundary,
        &ProgramMemory,
        &ProgramMemoryBoundary,
        &ReadWriteMemory,
        &PrivateMemoryBoundary,
        &ADD,
        &ADDI,
        &RANGE8,
        &RANGE16,
        &RANGE64,
        &RANGE128,
        &RANGE256,
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
        verify_logup_sum(&[claimed_sum], &view, &assert_ctx.lookup_elements).unwrap();
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
