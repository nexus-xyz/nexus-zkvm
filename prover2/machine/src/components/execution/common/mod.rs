use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::{component::ComponentTrace, eval::TraceEval, program::ProgramStep};

use crate::{
    components::execution::decoding::{ComponentDecodingTrace, DecodingColumn},
    lookups::{
        InstToProgMemoryLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::SideNote,
};

/// Main (original) trace columns shared by execution components.
pub trait ExecutionComponentColumn: AirColumn {
    const COLUMNS: [Self; 5];
}

macro_rules! derive_execution_column {
    ($col:ty) => {
        impl crate::components::execution::common::ExecutionComponentColumn for $col {
            // [is_local_pad, clk, clk_next, pc, pc_next]
            const COLUMNS: [Self; 5] = [
                Self::IsLocalPad,
                Self::Clk,
                Self::ClkNext,
                Self::Pc,
                Self::PcNext,
            ];
        }
    };
}
pub(crate) use derive_execution_column;

pub trait ExecutionComponent {
    const OPCODE: BuiltinOpcode;

    const REG1_ACCESSED: bool;
    const REG2_ACCESSED: bool;
    const REG3_ACCESSED: bool;
    const REG3_WRITE: bool;

    type Column: ExecutionComponentColumn;

    fn iter_program_steps<'a>(side_note: &'a SideNote) -> impl Iterator<Item = ProgramStep<'a>> {
        let opcode = Self::OPCODE;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                step_opcode if step_opcode == Some(opcode),
            )
        })
    }

    fn generate_interaction_trace(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        side_note: &SideNote,
        (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory): &(
            InstToProgMemoryLookupElements,
            ProgramExecutionLookupElements,
            InstToRegisterMemoryLookupElements,
        ),
    ) {
        let [is_local_pad, clk, clk_next, pc, pc_next] =
            <Self::Column as ExecutionComponentColumn>::COLUMNS;

        let [is_local_pad] = component_trace.original_base_column(is_local_pad);
        let clk = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(clk);
        let clk_next = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(clk_next);

        let pc = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(pc);
        let pc_next = component_trace.original_base_column::<{ WORD_SIZE_HALVED }, _>(pc_next);

        let decoding_trace = ComponentDecodingTrace::new(
            component_trace.log_size(),
            Self::iter_program_steps(side_note),
        );
        let instr_val = decoding_trace.base_column::<{ WORD_SIZE }>(DecodingColumn::InstrVal);

        let [op_a] = decoding_trace.base_column(DecodingColumn::OpA);

        let zeroed_reg = || [0u32; WORD_SIZE].map(|byte| BaseField::from(byte).into());
        let (op_b, b_val) = if Self::REG1_ACCESSED {
            (decoding_trace.op_b(), decoding_trace.b_val())
        } else {
            (BaseField::zero().into(), zeroed_reg())
        };
        let (op_c, c_val) = if Self::REG2_ACCESSED {
            (decoding_trace.op_c(), decoding_trace.c_val())
        } else {
            (BaseField::zero().into(), zeroed_reg())
        };
        let a_val = decoding_trace.a_val();

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            rel_inst_to_prog_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        );
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        logup_trace_builder.add_to_relation_with(
            rel_cont_prog_exec,
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
            rel_inst_to_reg_memory,
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
    }

    fn constrain_logups<E: EvalAtRow, P: PreprocessedAirColumn>(
        eval: &mut E,
        trace_eval: &TraceEval<P, Self::Column, E>,
        (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory): (
            &InstToProgMemoryLookupElements,
            &ProgramExecutionLookupElements,
            &InstToRegisterMemoryLookupElements,
        ),
        reg_addrs: [E::F; 3],
        reg_values: [[E::F; WORD_SIZE]; 3],
        instr_val: [E::F; WORD_SIZE],
    ) {
        let [is_local_pad, clk, clk_next, pc, pc_next] =
            <Self::Column as ExecutionComponentColumn>::COLUMNS;

        let [is_local_pad] = trace_eval.column_eval(is_local_pad);
        let clk = trace_eval.column_eval::<{ WORD_SIZE_HALVED }>(clk);
        let clk_next = trace_eval.column_eval::<{ WORD_SIZE_HALVED }>(clk_next);

        let pc = trace_eval.column_eval::<{ WORD_SIZE_HALVED }>(pc);
        let pc_next = trace_eval.column_eval::<{ WORD_SIZE_HALVED }>(pc_next);

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
                &reg_addrs,
                &reg_values[0],
                &reg_values[1],
                &reg_values[2],
                &[
                    BaseField::from(Self::REG1_ACCESSED as u32).into(),
                    BaseField::from(Self::REG2_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_ACCESSED as u32).into(),
                    BaseField::from(Self::REG3_WRITE as u32).into(),
                ],
            ]
            .concat(),
        ));
    }
}
