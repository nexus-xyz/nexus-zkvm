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
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    original_base_column,
    program::ProgramStep,
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::{ExecutionComponent, ExecutionLookupEval},
            load::columns::load_instr_val,
        },
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
        ProgramExecutionLookupElements, RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod lb;
mod lh;
mod lw;

mod lbu;
mod lhu;

mod decoding;

mod columns;
use columns::{Column, PreprocessedColumn};
use decoding::Decoding;

pub trait LoadOp: Sized + Sync + 'static {
    const RAM2_ACCESSED: bool;
    const RAM3_4ACCESSED: bool;
    const OPCODE: BuiltinOpcode;

    type LocalColumn: AirColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    );
    /// Add constraints for load instruction, returns evaluations for ram values and register values.
    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        local_trace_eval: &TraceEval<EmptyPreprocessedColumn, Self::LocalColumn, E>,
        range_check: &RangeCheckLookupElements,
    ) -> [[E::F; WORD_SIZE]; 2];
    /// Returns finalized columns for rw-memory component logup.
    ///
    /// Sign extended bytes are expected to be zeroed by the read-write memory component.
    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE];
    /// Add logup columns for the local trace.
    fn generate_interaction_trace(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    );
}

pub struct Load<T> {
    _phantom: PhantomData<T>,
}

impl<T: LoadOp> ExecutionComponent for Load<T> {
    const OPCODE: BuiltinOpcode = <T as LoadOp>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;
}

impl<T: LoadOp> Load<T> {
    const RAM1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const RAM_WRITE: BaseField = BaseField::from_u32_unchecked(0);

    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn generate_common_trace_row(
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

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let (h_ram_base_addr, h_carry) = add_with_carries(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);

        trace.fill_columns(row_idx, h_ram_base_addr, Column::HRamBaseAddr);
        trace.fill_columns(row_idx, [h_carry[1], h_carry[3]], Column::HCarry);

        Decoding::generate_decoding_trace_row(trace, row_idx, program_step, range_check_accum);
    }
}

impl<T: LoadOp> BuiltInComponent for Load<T> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToRamLookupElements,
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
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
        let num_load_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_load_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);
        let mut range_check_accum = RangeCheckAccumulator::default();

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_common_trace_row(
                &mut common_trace,
                row_idx,
                program_step,
                &mut range_check_accum,
            );
            T::generate_trace_row(
                row_idx,
                &mut local_trace,
                program_step,
                &mut range_check_accum,
            );
        }
        side_note.range_check.append(range_check_accum);
        // fill padding
        for row_idx in num_load_steps..1 << log_size {
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
            Column::COLUMNS_NUM + T::LocalColumn::COLUMNS_NUM
        );
        let (
            rel_inst_to_ram,
            rel_inst_to_prog_memory,
            rel_cont_prog_exec,
            rel_inst_to_reg_memory,
            range_check,
        ) = Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);

        let h_ram_base_addr = original_base_column!(component_trace, Column::HRamBaseAddr);
        let ram_values = T::finalized_ram_values(&component_trace);

        let ram2_accessed = BaseField::from(T::RAM2_ACCESSED as u32);
        let ram3_4accessed = BaseField::from(T::RAM3_4ACCESSED as u32);

        Decoding::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            &range_check,
        );
        T::generate_interaction_trace(&mut logup_trace_builder, &component_trace, &range_check);
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
            range_check,
        ) = lookup_elements;
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = columns::C_VAL.eval(&trace_eval);

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
        //     − b-val(1) − b-val(2) · 2^8
        //     − c-val(1) − c-val(2) · 2^8
        //     + h-carry(1) · 2^16
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[0].clone()
                    + h_ram_base_addr[1].clone() * BaseField::from(1 << 8)
                    - b_val[0].clone()
                    - b_val[1].clone() * BaseField::from(1 << 8)
                    - c_val[0].clone()
                    - c_val[1].clone() * BaseField::from(1 << 8)
                    + h_carry[0].clone() * BaseField::from(1 << 16)),
        );
        // (1 − is-local-pad) · (
        //     h-ram-base-addr(3) + h-ram-base-addr(4) · 2^8
        //     − h-carry(1)
        //     − b-val(3) − b-val(4) · 2^8
        //     − c-val(3) − c-val(4) · 2^8
        //     + h-carry(2) · 2^16
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[2].clone()
                    + h_ram_base_addr[3].clone() * BaseField::from(1 << 8)
                    - h_carry[0].clone()
                    - b_val[2].clone()
                    - b_val[3].clone() * BaseField::from(1 << 8)
                    - c_val[2].clone()
                    - c_val[3].clone() * BaseField::from(1 << 8)
                    + h_carry[1].clone() * BaseField::from(1 << 16)),
        );

        // h-carry(i) · (1 − h-carry(i)) = 0 for i = 1, 2
        for h_carry in h_carry {
            eval.add_constraint(h_carry.clone() * (E::F::one() - h_carry.clone()));
        }

        Decoding::constrain_decoding(eval, &trace_eval, range_check);

        let instr_val = load_instr_val(T::OPCODE.raw(), T::OPCODE.fn3().value()).eval(&trace_eval);
        let op_a = columns::OP_A.eval(&trace_eval);
        let op_b = columns::OP_B.eval(&trace_eval);
        let op_c = E::F::zero();

        let local_trace_eval = TraceEval::<EmptyPreprocessedColumn, T::LocalColumn, E>::new(eval);
        let [ram_values, reg3_value] =
            T::add_constraints(eval, &trace_eval, &local_trace_eval, range_check);

        let ram2_accessed = E::F::from(BaseField::from(T::RAM2_ACCESSED as u32));
        let ram3_4accessed = E::F::from(BaseField::from(T::RAM3_4ACCESSED as u32));
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
                reg_values: [reg3_value, b_val, zero_array::<WORD_SIZE, E>()],
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

pub const LB: Load<lb::Lb> = Load::new();
pub const LH: Load<lh::Lh> = Load::new();
pub const LW: Load<lw::Lw> = Load::new();

pub const LBU: Load<lbu::Lbu> = Load::new();
pub const LHU: Load<lhu::Lhu> = Load::new();

#[cfg(test)]
pub mod tests {
    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, ReadWriteMemory,
            ReadWriteMemoryBoundary, RegisterMemory, RegisterMemoryBoundary, ADD, ADDI, RANGE128,
            RANGE16, RANGE256, RANGE64, RANGE8,
        },
        framework::{
            test_utils::{assert_component, components_claimed_sum, AssertContext},
            MachineComponent,
        },
    };

    pub fn setup_ir() -> Vec<Instruction> {
        vec![
            // First we create a usable address. heap start: 0x81008, heap end: 0x881008
            // Aiming to create >=0x81008
            // TODO: shrink the following sequence of ADDs using SLL when it's available
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // repeat doubling x1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x8
            // Copying x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x100
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x1000
            // Adding x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x20000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x100000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            // Now x2 should be 0x101008
        ]
    }

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
        &RANGE8,
        &RANGE16,
        &RANGE64,
        &RANGE128,
        &RANGE256,
    ];

    fn assert_load_constraints<C>(component: C, opcode: BuiltinOpcode)
    where
        C: BuiltInComponent + 'static + Sync,
        C::LookupElements: 'static + Sync,
    {
        let mut instr = setup_ir();
        instr.push(Instruction::new_ir(Opcode::from(opcode), 5, 2, 0));
        let (view, program_trace) =
            k_trace_direct(&vec![BasicBlock::new(instr)], 1).expect("error generating trace");
        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = assert_component(component, assert_ctx);
        claimed_sum += components_claimed_sum(BASE_TEST_COMPONENTS, assert_ctx);
        assert!(claimed_sum.is_zero());
    }

    #[test]
    fn assert_lb_constraints() {
        assert_load_constraints(LB, BuiltinOpcode::LB);
    }

    #[test]
    fn assert_lh_constraints() {
        assert_load_constraints(LH, BuiltinOpcode::LH);
    }

    #[test]
    fn assert_lw_constraints() {
        assert_load_constraints(LW, BuiltinOpcode::LW);
    }

    #[test]
    fn assert_lbu_constraints() {
        assert_load_constraints(LBU, BuiltinOpcode::LBU);
    }

    #[test]
    fn assert_lhu_constraints() {
        assert_load_constraints(LHU, BuiltinOpcode::LHU);
    }
}
