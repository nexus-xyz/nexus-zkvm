use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::{ExecutionComponent, ExecutionLookupEval},
            decoding::{
                type_u::{self, TypeUDecoding},
                InstructionDecoding,
            },
        },
        utils::{
            add_16bit_with_carry,
            constraints::{ClkIncrement, PcIncrement},
            u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
        RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub const LUI: Lui = Lui;

pub struct Lui;

impl ExecutionComponent for Lui {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::LUI;

    const REG1_ACCESSED: bool = false;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;
}

struct LuiDecoding;
impl TypeUDecoding for LuiDecoding {
    const OPCODE: BuiltinOpcode = Lui::OPCODE;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

type Decoding = type_u::TypeU<LuiDecoding>;

impl Lui {
    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (_pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);
    }
}

impl BuiltInComponent for Lui {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
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
        let num_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut decoding_trace = TraceBuilder::new(log_size);
        let mut range_check_accum = RangeCheckAccumulator::default();

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
            type_u::generate_trace_row(
                row_idx,
                &mut decoding_trace,
                program_step,
                &mut range_check_accum,
            );
        }
        side_note.range_check.append(range_check_accum);
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(decoding_trace.finalize())
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
            Column::COLUMNS_NUM + type_u::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);
        Decoding::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            &range_check,
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
        let [is_local_pad] = trace_eval.column_eval(Column::IsLocalPad);
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            lookup_elements;

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

        let decoding_trace_eval =
            TraceEval::<EmptyPreprocessedColumn, type_u::DecodingColumn, E>::new(eval);
        Decoding::constrain_decoding(eval, &trace_eval, &decoding_trace_eval, range_check);

        // Logup Interactions
        let c_val = type_u::CVal.eval(&decoding_trace_eval);
        let reg_addrs = Decoding::combine_reg_addresses(&decoding_trace_eval);
        let instr_val = Decoding::combine_instr_val(&decoding_trace_eval);

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            ExecutionLookupEval {
                is_local_pad,
                reg_addrs,
                reg_values: [
                    c_val,
                    zero_array::<WORD_SIZE, E>(),
                    zero_array::<WORD_SIZE, E>(),
                ],
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, RANGE16, RANGE256, RANGE64,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_lui_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Case 1: LUI with a small positive value
            // LUI x1, 0x1 (Load 0x1000 into x1)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 1, 0, 0x1),
            // Case 2: LUI with a large positive value
            // LUI x2, 0xFFFFF (Load 0xFFFFF000 into x2)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 2, 0, 0xFFFFF),
            // Case 3: LUI with zero
            // LUI x3, 0x0 (Load 0x0 into x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 3, 0, 0x0),
            // Case 4: LUI with a value that sets some lower bits
            // LUI x4, 0xABCDE (Load 0xABCDE000 into x4)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 4, 0, 0xABCDE),
            // Case 5: LUI with x0 as destination (should not change x0)
            // LUI x0, 0x12345 (Should not change x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LUI), 0, 0, 0x12345),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(Lui, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &RANGE16,
                &RANGE64,
                &RANGE256,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
