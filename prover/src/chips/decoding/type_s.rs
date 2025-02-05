use stwo_prover::{constraint_framework::logup::LookupElements, core::fields::m31::BaseField};

use crate::{
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::TraceEval, sidenote::SideNote, ProgramStep, TracesBuilder},
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::riscv::InstructionType::SType;

use crate::column::Column;

use crate::trace::eval::trace_eval;

pub struct TypeSChip;

impl MachineChip for TypeSChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => {
                return;
            }
        };
        let step = &vm_step.step;
        if step.instruction.ins_type != SType {
            return;
        }
        let op_c_raw = vm_step.step.instruction.op_c;
        let op_c0 = (op_c_raw & 0b1) as u8;
        let op_c1_4 = ((op_c_raw >> 1) & 0b1111) as u8;
        let op_c5_7 = ((op_c_raw >> 5) & 0b111) as u8;
        let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
        let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
        traces.fill_columns(row_idx, op_c0, Column::OpC0);
        traces.fill_columns(row_idx, op_c1_4, Column::OpC1_4);
        traces.fill_columns(row_idx, op_c5_7, Column::OpC5_7);
        traces.fill_columns(row_idx, op_c8_10, Column::OpC8_10);
        traces.fill_columns(row_idx, op_c11, Column::OpC11);

        let op_a_raw = vm_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0b1111;

        traces.fill_columns(row_idx, op_a0, Column::OpA0);
        traces.fill_columns(row_idx, op_a1_4, Column::OpA1_4);

        let op_b_raw = vm_step.step.instruction.op_b as u8;
        let op_b0_3 = op_b_raw & 0b1111;
        let op_b4 = (op_b_raw >> 4) & 0b1;
        traces.fill_columns(row_idx, op_b0_3, Column::OpB0_3);
        traces.fill_columns(row_idx, op_b4, Column::OpB4);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_type_s] = virtual_column::IsTypeS::eval(trace_eval);
        let [op_c0] = trace_eval!(trace_eval, Column::OpC0);
        let [op_c1_4] = trace_eval!(trace_eval, Column::OpC1_4);
        let [op_c5_7] = trace_eval!(trace_eval, Column::OpC5_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);

        // Making sure that op_c matches its parts
        // is_type_s・ (op_c0 + op_c1_4・2 + op_c5_7・2^5 + op_c8_10・2^8 + op_c11・2^11 – op_c) = 0
        eval.add_constraint(
            is_type_s.clone()
                * (op_c0.clone()
                    + op_c1_4.clone() * BaseField::from(2)
                    + op_c5_7.clone() * BaseField::from(1 << 5)
                    + op_c8_10.clone() * BaseField::from(1 << 8)
                    + op_c11.clone() * BaseField::from(1 << 11)
                    - op_c.clone()),
        );

        // Computing c_val limbs and performing sign extension
        // is_type_s・ (op_c0 + op_c1_4・2 + op_c5_7・2^5 – c_val_1) = 0	 // limb 1
        // is_type_s・ (op_c8_10 + op_c11・(2^5-1)·2^3 – c_val_2) = 0	    // limb 2
        // is_type_s・ (op_c11・(2^8-1) – c_val_3) = 0			            // limb 3
        // is_type_s・ (op_c11・(2^8-1) – c_val_4) = 0			            // limb 4

        let value_c = trace_eval!(trace_eval, Column::ValueC);
        eval.add_constraint(
            is_type_s.clone()
                * (op_c0.clone()
                    + op_c1_4.clone() * BaseField::from(2)
                    + op_c5_7.clone() * BaseField::from(1 << 5)
                    - value_c[0].clone()),
        );

        eval.add_constraint(
            is_type_s.clone()
                * (op_c8_10.clone() + op_c11.clone() * BaseField::from(((1 << 5) - 1) * (1 << 3))
                    - value_c[1].clone()),
        );

        eval.add_constraint(
            is_type_s.clone()
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - value_c[2].clone()),
        );

        eval.add_constraint(
            is_type_s.clone()
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - value_c[3].clone()),
        );

        let [op_a] = trace_eval!(trace_eval, Column::OpA);
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, Column::OpA1_4);

        // Making sure that op_a matches its parts
        // is_type_s・ (op_a0 + op_a1_4・2 – op_a) = 0
        eval.add_constraint(
            is_type_s.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a.clone()),
        );

        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        let [op_b0_3] = trace_eval!(trace_eval, Column::OpB0_3);
        let [op_b4] = trace_eval!(trace_eval, Column::OpB4);
        // Making sure that op_b matches its parts
        // is_type_s・ (op_b0_3 + op_b4・2^4 – op_b) = 0
        eval.add_constraint(
            is_type_s.clone()
                * (op_b0_3.clone() + op_b4.clone() * BaseField::from(1 << 4) - op_b.clone()),
        );

        let [is_sb] = trace_eval!(trace_eval, Column::IsSb);
        let [is_sh] = trace_eval!(trace_eval, Column::IsSh);
        let [is_sw] = trace_eval!(trace_eval, Column::IsSw);
        let value_instr = trace_eval!(trace_eval, Column::InstrVal);

        // op_a, op_b, op_c range check follows from other range checks specified above
        // (is_type_s) ・ (b0100011 + op_c0・2^7 - instr_val_1) = 0	            // limb 1
        // (is_sb) ・ (op_c1_4 + b000・2^4 + op_a0・2^7 - instr_val_2) = 0	// limb 2 - sb
        // (is_sh) ・ (op_c1_4 + b001・2^4 + op_a0・2^7 - instr_val_2) = 0	// limb 2 - sh
        // (is_sw) ・ (op_c1_4 + b010・2^4 + op_a0・2^7 - instr_val_2) = 0	// limb 2 - sw
        // (is_type_s) ・ (op_a1_4 + op_b0_3・2^4 - instr_val_3) = 0             // limb 3
        // (is_type_s) ・ (op_b4 + op_c5_7・2 + op_c8_10・2^4 + op_c11・2^7 - instr_val_4) = 0 // limb 4

        eval.add_constraint(
            is_type_s.clone()
                * (E::F::from(BaseField::from(0b0100011))
                    + op_c0.clone() * BaseField::from(1 << 7)
                    - value_instr[0].clone()),
        );

        eval.add_constraint(
            is_sb
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b000)) * BaseField::from(1 << 4)
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_sh
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b001)) * BaseField::from(1 << 4)
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_sw
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b010)) * BaseField::from(1 << 4)
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );

        eval.add_constraint(
            is_type_s.clone()
                * (op_a1_4.clone() + op_b0_3.clone() * BaseField::from(1 << 4)
                    - value_instr[2].clone()),
        );

        eval.add_constraint(
            is_type_s.clone()
                * (op_b4
                    + op_c5_7 * BaseField::from(2)
                    + op_c8_10 * BaseField::from(1 << 4)
                    + op_c11 * BaseField::from(1 << 7)
                    - value_instr[3].clone()),
        );
    }
}
