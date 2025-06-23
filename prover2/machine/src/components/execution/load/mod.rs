use std::marker::PhantomData;

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

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::{ComponentTrace, FinalizedColumn},
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
};

use crate::{
    components::utils::{add_16bit_with_carry, add_with_carries, u32_to_16bit_parts_le},
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, CpuToInstLookupElements,
        InstToRamLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::SideNote,
};

mod lb;
mod lh;
mod lw;

mod lbu;
mod lhu;

mod columns;
use columns::{Column, PreprocessedColumn};

pub trait LoadOp: Sized + Sync + 'static {
    const RAM2_ACCESSED: bool;
    const RAM3_4ACCESSED: bool;
    const OPCODE: BuiltinOpcode;

    type LocalColumn: AirColumn;

    fn generate_trace_row(
        row_idx: usize,
        trace: &mut TraceBuilder<Self::LocalColumn>,
        program_step: ProgramStep,
    );
    /// Add constraints for load instruction, returns evaluations for ram values and register values.
    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: TraceEval<
            <Load<Self> as BuiltInComponent>::PreprocessedColumn,
            <Load<Self> as BuiltInComponent>::MainColumn,
            E,
        >,
    ) -> [[E::F; WORD_SIZE]; 2];
    /// Returns finalized columns for rw-memory component logup.
    ///
    /// Sign extended bytes are expected to be zeroed by the read-write memory component.
    fn finalized_ram_values(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE];
    /// Returns finalized columns for register memory component logup.
    fn finalized_reg3_value(component_trace: &ComponentTrace) -> [FinalizedColumn; WORD_SIZE];
}

pub struct Load<L> {
    _phantom: PhantomData<L>,
}

impl<L: LoadOp> Load<L> {
    const RAM1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const RAM_WRITE: BaseField = BaseField::from_u32_unchecked(0);

    const REG1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rs1 is read
    const REG2_ACCESSED: BaseField = BaseField::from_u32_unchecked(0); // rs2 is unused

    const REG3_ACCESSED: BaseField = BaseField::from_u32_unchecked(1); // rd is written
    const REG3_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    const fn opcode(&self) -> BaseField {
        BaseField::from_u32_unchecked(L::OPCODE.raw() as u32)
    }

    fn iter_program_steps<'a>(
        &self,
        side_note: &SideNote<'a>,
    ) -> impl Iterator<Item = ProgramStep<'a>> {
        let load_opcode = L::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                opcode if opcode == Some(load_opcode),
            )
        })
    }

    fn generate_common_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(L::OPCODE));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();

        let (h_ram_base_addr, h_carry) = add_with_carries(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);

        trace.fill_columns(row_idx, h_ram_base_addr, Column::HRamBaseAddr);
        trace.fill_columns(row_idx, [h_carry[1], h_carry[3]], Column::HCarry);
    }
}

impl<L: LoadOp> BuiltInComponent for Load<L> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToRamLookupElements,
        CpuToInstLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_load_steps = self.iter_program_steps(side_note).count();
        let log_size = num_load_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut local_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in self.iter_program_steps(side_note).enumerate() {
            self.generate_common_trace_row(&mut common_trace, row_idx, program_step);
            L::generate_trace_row(row_idx, &mut local_trace, program_step);
        }
        // fill padding
        for row_idx in num_load_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(local_trace.finalize())
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (rel_inst_to_ram, rel_cpu_to_inst, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        // finalized trace size wouldn't match common trace size, make unchecked calls

        let [is_local_pad] = component_trace.original_base_column_unchecked(Column::IsLocalPad);
        let clk: [_; WORD_SIZE_HALVED] =
            component_trace.original_base_column_unchecked(Column::Clk);
        let pc: [_; WORD_SIZE_HALVED] = component_trace.original_base_column_unchecked(Column::Pc);
        let clk_next: [_; WORD_SIZE_HALVED] =
            component_trace.original_base_column_unchecked(Column::ClkNext);
        let pc_next: [_; WORD_SIZE_HALVED] =
            component_trace.original_base_column_unchecked(Column::PcNext);

        let h_ram_base_addr: [_; WORD_SIZE] =
            component_trace.original_base_column_unchecked(Column::HRamBaseAddr);
        let ram_values = L::finalized_ram_values(&component_trace);
        let reg3_value = L::finalized_reg3_value(&component_trace);

        let b_val: [_; WORD_SIZE] = component_trace.original_base_column_unchecked(Column::BVal);
        let c_val: [_; WORD_SIZE] = component_trace.original_base_column_unchecked(Column::CVal);

        // consume(rel-cpu-to-inst, 1−is-local-pad, (clk, opcode, pc, a-val, b-val, c-val))
        logup_trace_builder.add_to_relation_with(
            &rel_cpu_to_inst,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[
                &clk,
                std::slice::from_ref(&self.opcode().into()),
                &pc,
                &reg3_value,
                &b_val,
                &c_val,
            ]
            .concat(),
        );
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[clk_next, pc_next].concat(),
        );

        let ram2_accessed = BaseField::from(L::RAM2_ACCESSED as u32);
        let ram3_4accessed = BaseField::from(L::RAM3_4ACCESSED as u32);
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
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (clk, a-val, b-val, c-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &reg3_value,
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
        // (h_ram_base_addr(1) + h_ram_base_addr(2) * 2^8 − b-val(1) − b-val(2) * 2^8 − c-val(1) − c-val(2) * 2^8 + h_carry(1) * 2^16) = 0
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
        // (1 − is-local-pad) *
        // (h_ram_base_addr(3) + h_ram_base_addr(4) * 2^8 − b-val(3) − b-val(4) * 2^8 − c-val(3) − c-val(4) * 2^8 + h_carry(2) * 2^16) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr[2].clone()
                    + h_ram_base_addr[3].clone() * BaseField::from(1 << 8)
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

        let [ram_values, reg3_value] = L::add_constraints(eval, trace_eval);

        let (rel_inst_to_ram, rel_cpu_to_inst, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            lookup_elements;

        // consume(rel-cpu-to-inst, 1 − is-local-pad, (clk, opcode, pc, a-val, b-val, c-val))
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_inst,
            (is_local_pad.clone() - E::F::one()).into(),
            &[
                &clk,
                std::slice::from_ref(&E::F::from(self.opcode())),
                &pc,
                &reg3_value,
                &b_val,
                &c_val,
            ]
            .concat(),
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

        let ram2_accessed = E::F::from(BaseField::from(L::RAM2_ACCESSED as u32));
        let ram3_4accessed = E::F::from(BaseField::from(L::RAM3_4ACCESSED as u32));
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
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (clk, a-val, b-val, c-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &reg3_value,
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

        eval.finalize_logup_in_pairs();
    }
}

pub const LB: Load<lb::Lb> = Load::new();
pub const LH: Load<lh::Lh> = Load::new();
pub const LW: Load<lw::Lw> = Load::new();

pub const LBU: Load<lbu::Lbu> = Load::new();
pub const LHU: Load<lhu::Lhu> = Load::new();

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
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, ReadWriteMemory,
            ReadWriteMemoryBoundary, RegisterMemory, RegisterMemoryBoundary, ADD, ADDI,
        },
        framework::{
            test_utils::{assert_component, components_claimed_sum, AssertContext},
            MachineComponent,
        },
    };

    fn setup_ir() -> Vec<Instruction> {
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
            // here x1 should be 0x10000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 1, 1, 1),
            // here x1 should be 0x80000
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            // Now x2 should be 0x81008
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
