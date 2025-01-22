use stwo_prover::{constraint_framework::logup::LookupElements, core::fields::m31::BaseField};

use crate::{
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::TraceEval, program_trace::ProgramTracesBuilder, sidenote::SideNote, ProgramStep,
        TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::riscv::InstructionType::UType;

use crate::column::Column::{self, OpA, OpA0, OpA14, OpC, OpC12_15, OpC16_23, OpC24_31, ValueC};

use crate::trace::eval::trace_eval;

pub struct TypeUChip;

impl MachineChip for TypeUChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_trace: &mut ProgramTracesBuilder,
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

        let op_a = vm_step.step.instruction.op_a;
        let op_a0 = op_a as u8 & 0x1;
        let op_a14 = (op_a as u8 >> 1) & 0xF;
        traces.fill_columns(row_idx, op_a0, OpA0);
        traces.fill_columns(row_idx, op_a14, OpA14);
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

        // is_type_u・ (op_a0 + op_a1_4・2 – op_a) = 0
        let [op_a0] = trace_eval!(trace_eval, OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, OpA14);
        let [op_a] = trace_eval!(trace_eval, OpA);
        eval.add_constraint(
            is_type_u.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a.clone()),
        );

        // (is_type_u)・ (op_b) = 0
        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        eval.add_constraint(is_type_u.clone() * op_b.clone());

        // (is_type_u)・ (b_val_1) = 0
        // (is_type_u)・ (b_val_2) = 0
        // (is_type_u)・ (b_val_3) = 0
        // (is_type_u)・ (b_val_4) = 0
        let b_val = trace_eval!(trace_eval, Column::ValueB);
        for b_val_limb in b_val.iter() {
            eval.add_constraint(is_type_u.clone() * b_val_limb.clone());
        }

        // is_lui ・ (b0110111 + op_a0・2^7 - instr_val_1) = 0
        let instr_val = trace_eval!(trace_eval, Column::InstrVal);
        let [is_lui] = trace_eval!(trace_eval, Column::IsLui);
        let lui_opcode: E::F = BaseField::from(0b0110111).into();
        eval.add_constraint(
            is_lui.clone()
                * (lui_opcode + op_a0.clone() * BaseField::from(1 << 7) - instr_val[0].clone()),
        );

        // is_auipc ・ (b0010111 + op_a0・2^7 - instr_val_1) = 0
        let [is_auipc] = trace_eval!(trace_eval, Column::IsAuipc);
        let auipc_opcode: E::F = BaseField::from(0b0010111).into();
        eval.add_constraint(
            is_auipc.clone()
                * (auipc_opcode + op_a0.clone() * BaseField::from(1 << 7) - instr_val[0].clone()),
        );

        // is_type_u ・ (op_a1_4 + op_c12_15・2^4 - instr_val_2) = 0
        eval.add_constraint(
            is_type_u.clone()
                * (op_a1_4.clone() + op_c12_15.clone() * BaseField::from(1 << 4)
                    - instr_val[1].clone()),
        );

        // is_type_u ・ (op_c16_23 - instr_val_3) = 0
        eval.add_constraint(is_type_u.clone() * (op_c16_23.clone() - instr_val[2].clone()));

        // is_type_u ・ (op_c24_31 - instr_val_4) = 0
        eval.add_constraint(is_type_u.clone() * (op_c24_31.clone() - instr_val[3].clone()));
    }
}
