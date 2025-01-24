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

use nexus_vm::riscv::InstructionType::JType;

use crate::column::Column;

use crate::trace::eval::trace_eval;

pub struct TypeJChip;

impl MachineChip for TypeJChip {
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
        if step.instruction.ins_type != JType {
            return;
        }
        let op_c_raw = vm_step.step.instruction.op_c;

        // Fill auxiliary columns for type J immediate value parsing
        let op_c1_3 = ((op_c_raw >> 1) & 0b111) as u8;
        let op_c4_7 = ((op_c_raw >> 4) & 0b111) as u8;
        let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
        let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
        let op_c12_15 = ((op_c_raw >> 12) & 0b1111) as u8;
        let op_c16_19 = ((op_c_raw >> 16) & 0b1111) as u8;
        let op_c20 = ((op_c_raw >> 20) & 0b1) as u8;

        traces.fill_columns(row_idx, op_c1_3, Column::OpC1_3);
        traces.fill_columns(row_idx, op_c4_7, Column::OpC4_7);
        traces.fill_columns(row_idx, op_c8_10, Column::OpC8_10);
        traces.fill_columns(row_idx, op_c11, Column::OpC11);
        traces.fill_columns(row_idx, op_c12_15, Column::OpC12_15);
        traces.fill_columns(row_idx, op_c16_19, Column::OpC16_19);
        traces.fill_columns(row_idx, op_c20, Column::OpC20);

        let op_a_raw = vm_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0b1111;

        traces.fill_columns(row_idx, op_a0, Column::OpA0);
        traces.fill_columns(row_idx, op_a1_4, Column::OpA1_4);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_type_j] = virtual_column::IsTypeJ::eval(trace_eval);
        let [op_c1_3] = trace_eval!(trace_eval, Column::OpC1_3);
        let [op_c4_7] = trace_eval!(trace_eval, Column::OpC4_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);
        let [op_c12_15] = trace_eval!(trace_eval, Column::OpC12_15);
        let [op_c16_19] = trace_eval!(trace_eval, Column::OpC16_19);
        let [op_c20] = trace_eval!(trace_eval, Column::OpC20);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);

        // Making sure that op_c matches its parts
        // is_type_j・ (op_c1_3・2 + op_c4_7・2^4  + op_c8_10・2^8 + op_c11・2^11 + op_c12_15・2^12 + op_c16_19・2^16 + op_c20・2^20 – op_c) = 0
        eval.add_constraint(
            is_type_j.clone()
                * (op_c1_3.clone() * BaseField::from(2)
                    + op_c4_7.clone() * BaseField::from(1 << 4)
                    + op_c8_10.clone() * BaseField::from(1 << 8)
                    + op_c11.clone() * BaseField::from(1 << 11)
                    + op_c12_15.clone() * BaseField::from(1 << 12)
                    + op_c16_19.clone() * BaseField::from(1 << 16)
                    + op_c20.clone() * BaseField::from(1 << 20)
                    - op_c.clone()),
        );

        let value_c = trace_eval!(trace_eval, Column::ValueC);

        // Computing c_val limbs and performing sign extension
        // is_type_j ・ (op_c1_3・2 + op_c4_7・2^4 - c_val_1) = 0                // limb 1 jal instructions
        // is_type_j ・ (op_c8_10 + op_c11・2^3 + op_c12_15・2^4 - c_val_2) = 0  // limb 2 jal instructions
        // is_type_j ・ (op_c16_19 + op_c20・(2^4-1)·2^4 - c_val_3) = 0          // limb 3 jal instructions
        // is_type_j ・ (op_c20・(2^8-1) - c_val_4) = 0      		             // limb 4 jal instructions
        eval.add_constraint(
            is_type_j.clone()
                * (op_c1_3.clone() * BaseField::from(2)
                    + op_c4_7.clone() * BaseField::from(1 << 4)
                    - value_c[0].clone()),
        );

        eval.add_constraint(
            is_type_j.clone()
                * (op_c8_10.clone()
                    + op_c11.clone() * BaseField::from(1 << 3)
                    + op_c12_15.clone() * BaseField::from(1 << 4)
                    - value_c[1].clone()),
        );

        eval.add_constraint(
            is_type_j.clone()
                * (op_c16_19.clone()
                    + op_c20.clone() * BaseField::from((1 << 4) - 1) * BaseField::from(1 << 4)
                    - value_c[2].clone()),
        );

        eval.add_constraint(
            is_type_j.clone()
                * (op_c20.clone() * BaseField::from((1 << 8) - 1) - value_c[3].clone()),
        );

        let [op_a] = trace_eval!(trace_eval, Column::OpA);
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, Column::OpA1_4);

        // Making sure that op_a matches its parts
        // is_type_j・ (op_a0 + op_a1_4・2 – op_a) = 0
        eval.add_constraint(
            is_type_j.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a.clone()),
        );

        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let [op_b] = trace_eval!(trace_eval, Column::OpB);

        // Making sure that op_b=0
        // (is_type_j)・ (op_b) = 0
        eval.add_constraint(is_type_j.clone() * op_b.clone());

        // Computing b_val limbs
        // (is_type_j)・ (b_val_1) = 0			// limb 1
        // (is_type_j)・ (b_val_2) = 0			// limb 2
        // (is_type_j)・ (b_val_3) = 0			// limb 3
        // (is_type_j)・ (b_val_4) = 0			// limb 4
        eval.add_constraint(is_type_j.clone() * value_b[0].clone());
        eval.add_constraint(is_type_j.clone() * value_b[1].clone());
        eval.add_constraint(is_type_j.clone() * value_b[2].clone());
        eval.add_constraint(is_type_j.clone() * value_b[3].clone());

        let [is_jal] = trace_eval!(trace_eval, Column::IsJal);
        let value_instr = trace_eval!(trace_eval, Column::InstrVal);
        // checking format of jal instruction
        // is_jal ・ (0b1101111 + op_a0・2^7 - instr_val_1) = 0                 // limb 1
        // is_jal ・ (op_a1_4 + op_c12_15・2^4 - instr_val_2) = 0               // limb 2
        // is_jal ・ (op_c16_19 + op_c11・2^4 + op_c1_3・2^5 - instr_val_3) = 0 // limb 3
        // is_jal ・ (op_c4_7 + op_c8_10・2^4 + op_c20・2^7 - instr_val_4) = 0  // limb 4

        eval.add_constraint(
            is_jal.clone()
                * (E::F::from(BaseField::from(0b1101111))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[0].clone()),
        );

        eval.add_constraint(
            is_jal.clone()
                * (op_a1_4.clone() + op_c12_15.clone() * BaseField::from(1 << 4)
                    - value_instr[1].clone()),
        );

        eval.add_constraint(
            is_jal.clone()
                * (op_c16_19.clone()
                    + op_c11.clone() * BaseField::from(1 << 4)
                    + op_c1_3.clone() * BaseField::from(1 << 5)
                    - value_instr[2].clone()),
        );

        eval.add_constraint(
            is_jal.clone()
                * (op_c4_7.clone()
                    + op_c8_10.clone() * BaseField::from(1 << 4)
                    + op_c20.clone() * BaseField::from(1 << 7)
                    - value_instr[3].clone()),
        );
    }
}
