use num_traits::{One, Zero};
use stwo::{core::fields::m31::BaseField, prover::backend::simd::m31::PackedBaseField};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_trace::{
    component::{ComponentTrace, FinalizedColumn},
    program::ProgramStep,
};

use crate::{
    lookups::{
        InstToProgMemoryLookupElements, InstToRegisterMemoryLookupElements, LogupTraceBuilder,
        ProgramExecutionLookupElements,
    },
    side_note::SideNote,
};

mod logup_gen;
pub use logup_gen::{ComponentTraceRef, ExecutionComponentColumn, ExecutionComponentTrace};

pub trait ExecutionComponent {
    const OPCODE: BuiltinOpcode;

    const REG1_ACCESSED: bool;
    const REG2_ACCESSED: bool;
    const REG3_ACCESSED: bool;
    const REG3_WRITE: bool;

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
        is_local_pad: FinalizedColumn,
    ) {
        let decoding_trace = ExecutionComponentTrace::new(
            component_trace.log_size(),
            Self::iter_program_steps(side_note),
        );
        let instr_val =
            decoding_trace.base_column::<{ WORD_SIZE_HALVED }>(ExecutionComponentColumn::InstrVal);

        let [op_a] = decoding_trace.base_column(ExecutionComponentColumn::OpA);
        let clk = decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::Clk);
        let clk_next =
            decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::ClkNext);
        let pc = decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::Pc);
        let pc_next =
            decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::PcNext);

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

    fn constrain_logups<E: EvalAtRow>(
        eval: &mut E,
        (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory): (
            &InstToProgMemoryLookupElements,
            &ProgramExecutionLookupElements,
            &InstToRegisterMemoryLookupElements,
        ),
        vals: ExecutionLookupEval<E::F>,
    ) {
        let ExecutionLookupEval {
            is_local_pad,
            reg_addrs,
            reg_values,
            instr_val,
            clk,
            clk_next,
            pc,
            pc_next,
        } = vals;
        // convert to 16-bit parts
        let instr_val: [E::F; WORD_SIZE_HALVED] = std::array::from_fn(|i| {
            instr_val[i * 2].clone() + instr_val[i * 2 + 1].clone() * BaseField::from(1 << 8)
        });

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

/// Evaluations of columns used in execution components lookups
pub struct ExecutionLookupEval<F> {
    pub is_local_pad: F,
    pub reg_addrs: [F; 3],
    pub reg_values: [[F; WORD_SIZE]; 3],
    pub instr_val: [F; WORD_SIZE],
    pub clk: [F; WORD_SIZE_HALVED],
    pub clk_next: [F; WORD_SIZE_HALVED],
    pub pc: [F; WORD_SIZE_HALVED],
    pub pc_next: [F; WORD_SIZE_HALVED],
}
