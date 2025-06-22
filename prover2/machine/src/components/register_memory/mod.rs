use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{m31::PackedBaseField, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::WORD_SIZE;
use nexus_vm_prover_trace::{
    builder::FinalizedTrace, component::ComponentTrace, eval::TraceEval, original_base_column,
    preprocessed_base_column, preprocessed_trace_eval, trace_eval,
};

use crate::{
    components::cpu::preprocessed_clk_trace,
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, CpuToRegisterMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, RegisterMemoryLookupElements,
    },
    side_note::SideNote,
};

mod columns;
mod trace;

mod reg3_constraints;
mod timestamp_constraints;

use columns::{Column, PreprocessedColumn};
use trace::preprocessed_timestamp_trace;
pub use trace::RegisterMemorySideNote;

pub struct RegisterMemory;

impl BuiltInComponent for RegisterMemory {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        RegisterMemoryLookupElements,
        InstToRegisterMemoryLookupElements,
        CpuToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = preprocessed_clk_trace(log_size);

        trace.extend(preprocessed_timestamp_trace(log_size, 2));
        trace.extend(preprocessed_timestamp_trace(log_size, 1));
        trace.extend(preprocessed_timestamp_trace(log_size, 0));

        FinalizedTrace {
            cols: trace,
            log_size,
        }
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        trace::generate_main_trace(side_note)
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
        let (rel_reg_memory_read_write, rel_inst_to_reg_memory, rel_cpu_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = preprocessed_base_column!(component_trace, PreprocessedColumn::Clk);
        let reg1_val = original_base_column!(component_trace, Column::Reg1Val);
        let reg2_val = original_base_column!(component_trace, Column::Reg2Val);
        let reg3_val = original_base_column!(component_trace, Column::Reg3Val);

        let [reg1_addr] = original_base_column!(component_trace, Column::Reg1Addr);
        let [reg2_addr] = original_base_column!(component_trace, Column::Reg2Addr);
        let [reg3_addr] = original_base_column!(component_trace, Column::Reg3Addr);

        let [reg1_accessed] = original_base_column!(component_trace, Column::Reg1Accessed);
        let [reg2_accessed] = original_base_column!(component_trace, Column::Reg2Accessed);
        let [reg3_accessed] = original_base_column!(component_trace, Column::Reg3Accessed);
        let [reg3_write] = original_base_column!(component_trace, Column::Reg3Write);

        // consume(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (clk, reg3-val, reg1-val, reg2-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[
                clk.as_slice(),
                &reg3_val,
                &reg1_val,
                &reg2_val,
                &[reg1_accessed, reg2_accessed, reg3_accessed, reg3_write],
            ]
            .concat(),
        );

        // consume(rel-cpu-to-reg-memory, 1 − is-local-pad, (clk, reg3-addr, reg1-addr, reg2-addr))
        logup_trace_builder.add_to_relation_with(
            &rel_cpu_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[clk.as_slice(), &[reg3_addr, reg1_addr, reg2_addr]].concat(),
        );

        // consume(rel-reg-memory-read-write, reg1-accessed, (reg1-addr, reg1-val, reg1-ts-prev))
        RegisterMemory::consume_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg1Accessed,
            Column::Reg1Addr,
            Column::Reg1Val,
            Column::Reg1TsPrev,
        );
        // consume(rel-reg-memory-read-write, reg2-accessed, (reg2-addr, reg2-val, reg2-ts-prev))
        RegisterMemory::consume_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg2Accessed,
            Column::Reg2Addr,
            Column::Reg2Val,
            Column::Reg2TsPrev,
        );
        // consume(rel-reg-memory-read-write, reg3-accessed, (reg3-addr, reg3-val-prev, reg3-ts-prev))
        RegisterMemory::consume_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg3Accessed,
            Column::Reg3Addr,
            Column::Reg3ValPrev,
            Column::Reg3TsPrev,
        );
        // provide(rel-reg-memory-read-write, reg1-accessed, (reg1-addr, reg1-val, reg1-ts-cur))
        RegisterMemory::provide_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg1Accessed,
            Column::Reg1Addr,
            Column::Reg1Val,
            PreprocessedColumn::Reg1TsCur,
        );
        // provide(rel-reg-memory-read-write, reg2-accessed, (reg2-addr, reg2-val, reg2-ts-cur))
        RegisterMemory::provide_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg2Accessed,
            Column::Reg2Addr,
            Column::Reg2Val,
            PreprocessedColumn::Reg2TsCur,
        );
        // provide(rel-reg-memory-read-write, reg3-accessed, (reg3-addr, reg3-val-cur, reg3-ts-cur))
        RegisterMemory::provide_access(
            &mut logup_trace_builder,
            &component_trace,
            &rel_reg_memory_read_write,
            Column::Reg3Accessed,
            Column::Reg3Addr,
            Column::Reg3ValCur,
            PreprocessedColumn::Reg3TsCur,
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        RegisterMemory::constrain_timestamps(eval, &trace_eval);
        RegisterMemory::constrain_reg3(eval, &trace_eval);

        // Logup Interactions
        let (rel_reg_memory_read_write, rel_inst_to_reg_memory, rel_cpu_to_reg_memory) =
            lookup_elements;

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let clk = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let reg1_val = trace_eval!(trace_eval, Column::Reg1Val);
        let reg2_val = trace_eval!(trace_eval, Column::Reg2Val);
        let reg3_val = trace_eval!(trace_eval, Column::Reg3Val);

        let [reg1_addr] = trace_eval!(trace_eval, Column::Reg1Addr);
        let [reg2_addr] = trace_eval!(trace_eval, Column::Reg2Addr);
        let [reg3_addr] = trace_eval!(trace_eval, Column::Reg3Addr);

        let [reg1_accessed] = trace_eval!(trace_eval, Column::Reg1Accessed);
        let [reg2_accessed] = trace_eval!(trace_eval, Column::Reg2Accessed);
        let [reg3_accessed] = trace_eval!(trace_eval, Column::Reg3Accessed);
        let [reg3_write] = trace_eval!(trace_eval, Column::Reg3Write);

        // consume(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (clk, reg3-val, reg1-val, reg2-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (is_local_pad.clone() - E::F::one()).into(),
            &[
                clk.as_slice(),
                &reg3_val,
                &reg1_val,
                &reg2_val,
                &[
                    reg1_accessed.clone(),
                    reg2_accessed.clone(),
                    reg3_accessed.clone(),
                    reg3_write.clone(),
                ],
            ]
            .concat(),
        ));

        // consume(rel-cpu-to-reg-memory, 1 − is-local-pad, (clk, reg3-addr, reg1-addr, reg2-addr))
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_reg_memory,
            (is_local_pad.clone() - E::F::one()).into(),
            &[clk.as_slice(), &[reg3_addr, reg1_addr, reg2_addr]].concat(),
        ));

        // consume(rel-reg-memory-read-write, reg1-accessed, (reg1-addr, reg1-val, reg1-ts-prev))
        RegisterMemory::constrain_consume_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg1Accessed,
            Column::Reg1Addr,
            Column::Reg1Val,
            Column::Reg1TsPrev,
        );
        // consume(rel-reg-memory-read-write, reg2-accessed, (reg2-addr, reg2-val, reg2-ts-prev))
        RegisterMemory::constrain_consume_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg2Accessed,
            Column::Reg2Addr,
            Column::Reg2Val,
            Column::Reg2TsPrev,
        );
        // consume(rel-reg-memory-read-write, reg3-accessed, (reg3-addr, reg3-val-prev, reg3-ts-prev))
        RegisterMemory::constrain_consume_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg3Accessed,
            Column::Reg3Addr,
            Column::Reg3ValPrev,
            Column::Reg3TsPrev,
        );
        // provide(rel-reg-memory-read-write, reg1-accessed, (reg1-addr, reg1-val, reg1-ts-cur))
        RegisterMemory::constrain_provide_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg1Accessed,
            Column::Reg1Addr,
            Column::Reg1Val,
            PreprocessedColumn::Reg1TsCur,
        );
        // provide(rel-reg-memory-read-write, reg2-accessed, (reg2-addr, reg2-val, reg2-ts-cur))
        RegisterMemory::constrain_provide_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg2Accessed,
            Column::Reg2Addr,
            Column::Reg2Val,
            PreprocessedColumn::Reg2TsCur,
        );
        // provide(rel-reg-memory-read-write, reg3-accessed, (reg3-addr, reg3-val-cur, reg3-ts-cur))
        RegisterMemory::constrain_provide_access(
            eval,
            &trace_eval,
            rel_reg_memory_read_write,
            Column::Reg3Accessed,
            Column::Reg3Addr,
            Column::Reg3ValCur,
            PreprocessedColumn::Reg3TsCur,
        );

        eval.finalize_logup_in_pairs();
    }
}

impl RegisterMemory {
    fn constrain_consume_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
        accessed: Column,
        reg_addr: Column,
        reg_val: Column,
        reg_ts_prev: Column,
    ) {
        let [accessed] = trace_eval.column_eval(accessed);
        let [reg_addr] = trace_eval.column_eval(reg_addr);
        let reg_val: [E::F; WORD_SIZE] = trace_eval.column_eval(reg_val);
        let reg_ts_prev: [E::F; WORD_SIZE] = trace_eval.column_eval(reg_ts_prev);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-accessed).into(),
            &[std::slice::from_ref(&reg_addr), &reg_val, &reg_ts_prev].concat(),
        ));
    }

    fn constrain_provide_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
        accessed: Column,
        reg_addr: Column,
        reg_val: Column,
        reg_ts_cur: PreprocessedColumn,
    ) {
        let [accessed] = trace_eval.column_eval(accessed);
        let [reg_addr] = trace_eval.column_eval(reg_addr);
        let reg_val: [E::F; WORD_SIZE] = trace_eval.column_eval(reg_val);
        let reg_ts_cur: [E::F; WORD_SIZE] = trace_eval.preprocessed_column_eval(reg_ts_cur);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (accessed).into(),
            &[std::slice::from_ref(&reg_addr), &reg_val, &reg_ts_cur].concat(),
        ));
    }

    fn consume_access(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        lookup_elements: &RegisterMemoryLookupElements,
        accessed: Column,
        reg_addr: Column,
        reg_val: Column,
        reg_ts_prev: Column,
    ) {
        let [accessed] = component_trace.original_base_column(accessed);
        let [reg_addr] = component_trace.original_base_column(reg_addr);
        let reg_val: [_; WORD_SIZE] = component_trace.original_base_column(reg_val);
        let reg_ts_prev: [_; WORD_SIZE] = component_trace.original_base_column(reg_ts_prev);

        logup_trace_builder.add_to_relation_with(
            lookup_elements,
            [accessed],
            |[accessed]| (-accessed).into(),
            &[std::slice::from_ref(&reg_addr), &reg_val, &reg_ts_prev].concat(),
        );
    }

    fn provide_access(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        lookup_elements: &RegisterMemoryLookupElements,
        accessed: Column,
        reg_addr: Column,
        reg_val: Column,
        reg_ts_cur: PreprocessedColumn,
    ) {
        let [accessed] = component_trace.original_base_column(accessed);
        let [reg_addr] = component_trace.original_base_column(reg_addr);
        let reg_val: [_; WORD_SIZE] = component_trace.original_base_column(reg_val);
        let reg_ts_cur: [_; WORD_SIZE] = component_trace.preprocessed_base_column(reg_ts_cur);

        logup_trace_builder.add_to_relation(
            lookup_elements,
            accessed,
            &[std::slice::from_ref(&reg_addr), &reg_val, &reg_ts_cur].concat(),
        );
    }
}

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
            register_memory_boundary::RegisterMemoryBoundary, Cpu, CpuBoundary, ProgramMemory,
            ProgramMemoryBoundary, ADD, ADDI,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };

    #[test]
    fn assert_register_memory_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
            // set reg3 = x0
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 0, 5, 4),
            // ADDI doesn't use reg2 and the timestamp is not zero
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = assert_component(RegisterMemory, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &RegisterMemoryBoundary,
                &ADD,
                &ADDI,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
