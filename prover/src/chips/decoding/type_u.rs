use stwo_prover::{constraint_framework::logup::LookupElements, core::fields::m31::BaseField};

use crate::{
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::TraceEval, program_trace::ProgramTraces, sidenote::SideNote, ProgramStep,
        TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::riscv::InstructionType::UType;

use crate::column::Column::{self, OpC, OpC12_15, OpC16_23, OpC24_31, ValueC};

use crate::trace::eval::trace_eval;

pub struct TypeUChip;

impl MachineChip for TypeUChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_trace: &ProgramTraces,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => {
                return;
            }
        };
        let step = &vm_step.step;
        if step.instruction.ins_type != UType {
            return;
        }
        let op_c_raw = vm_step.step.instruction.op_c;

        // Fill auxiliary columns for type U immediate value parsing
        let op_c12_15 = op_c_raw & 0xF;
        let op_c16_23 = (op_c_raw >> 4) & 0xFF;
        let op_c24_31 = (op_c_raw >> 12) & 0xFF;
        traces.fill_columns(row_idx, op_c12_15 as u8, OpC12_15);
        traces.fill_columns(row_idx, op_c16_23 as u8, OpC16_23);
        traces.fill_columns(row_idx, op_c24_31 as u8, OpC24_31);
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_type_u] = virtual_column::IsTypeU::eval(trace_eval);
        let [op_c12_15] = trace_eval!(trace_eval, OpC12_15);
        let [op_c16_23] = trace_eval!(trace_eval, OpC16_23);
        let [op_c24_31] = trace_eval!(trace_eval, OpC24_31);
        let [op_c] = trace_eval!(trace_eval, OpC);
        let value_c = trace_eval!(trace_eval, ValueC);

        // is_type_u・ (op_c12_15 + op_c16_23・2^4 + op_c24_31・2^{12} – op_c) = 0
        eval.add_constraint(
            is_type_u.clone()
                * (op_c12_15.clone()
                    + op_c16_23.clone() * BaseField::from(1 << 4)
                    + op_c24_31.clone() * BaseField::from(1 << 12)
                    - op_c.clone()),
        );

        // is_type_u・ (c_val_1) = 0
        eval.add_constraint(is_type_u.clone() * value_c[0].clone());
        // is_type_u・ (op_c_12_15・2^4 – c_val_2) = 0
        eval.add_constraint(
            is_type_u.clone() * (op_c12_15.clone() * BaseField::from(1 << 4) - value_c[1].clone()),
        );
        // is_type_u・ (op_c_16_23 – c_val_3) = 0
        eval.add_constraint(is_type_u.clone() * (op_c16_23.clone() - value_c[2].clone()));
        // is_type_u・ (op_c_24_32 – c_val_4) = 0
        eval.add_constraint(is_type_u.clone() * (op_c24_31.clone() - value_c[3].clone()));
    }
}
