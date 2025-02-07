use stwo_prover::core::fields::m31::BaseField;

use crate::{
    components::AllLookupElements,
    trace::{eval::TraceEval, sidenote::SideNote, ProgramStep, TracesBuilder},
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::riscv::InstructionType::BType;

use crate::column::Column;

use crate::trace::eval::trace_eval;

pub struct TypeBChip;

impl MachineChip for TypeBChip {
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
        if step.instruction.ins_type != BType {
            return;
        }
        let op_c_raw = vm_step.step.instruction.op_c;

        // Fill auxiliary columns for type B immediate value parsing
        let op_c1_4 = ((op_c_raw >> 1) & 0b1111) as u8;
        let op_c5_7 = ((op_c_raw >> 5) & 0b111) as u8;
        let op_c8_10 = ((op_c_raw >> 8) & 0b111) as u8;
        let op_c11 = ((op_c_raw >> 11) & 0b1) as u8;
        let op_c12 = ((op_c_raw >> 12) & 0b1) as u8;

        traces.fill_columns(row_idx, op_c1_4, Column::OpC1_4);
        traces.fill_columns(row_idx, op_c5_7, Column::OpC5_7);
        traces.fill_columns(row_idx, op_c8_10, Column::OpC8_10);
        traces.fill_columns(row_idx, op_c11, Column::OpC11);
        traces.fill_columns(row_idx, op_c12, Column::OpC12);

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
        _lookup_elements: &AllLookupElements,
    ) {
        let [is_type_b] = virtual_column::IsTypeB::eval(trace_eval);
        let [op_c1_4] = trace_eval!(trace_eval, Column::OpC1_4);
        let [op_c5_7] = trace_eval!(trace_eval, Column::OpC5_7);
        let [op_c8_10] = trace_eval!(trace_eval, Column::OpC8_10);
        let [op_c11] = trace_eval!(trace_eval, Column::OpC11);
        let [op_c12] = trace_eval!(trace_eval, Column::OpC12);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);

        // Making sure that op_c matches its parts

        // is_type_b・(op_c1_4・2 + op_c5_7・2^5 + op_c8_10・2^8 + op_c11・2^11 + op_c12・2^12 – op_c) = 0
        eval.add_constraint(
            is_type_b.clone()
                * (op_c1_4.clone() * BaseField::from(2)
                    + op_c5_7.clone() * BaseField::from(1 << 5)
                    + op_c8_10.clone() * BaseField::from(1 << 8)
                    + op_c11.clone() * BaseField::from(1 << 11)
                    + op_c12.clone() * BaseField::from(1 << 12)
                    - op_c.clone()),
        );

        let value_c = trace_eval!(trace_eval, Column::ValueC);

        // Computing c_val limbs and performing sign extension
        // (is_type_b)・ (op_c1_4・2 + op_c5_7・2^5 – c_val_1) = 0				        // limb 1
        // (is_type_b)・ (op_c8_10 + op_c11・2^3 + op_c12・(2^4-1)·2^4 – c_val_2) = 0   // limb 2
        // (is_type_b)・ (op_c12・(2^8-1) – c_val_3) = 0					            // limb 3
        // (is_type_b)・ (op_c12・(2^8-1) – c_val_4) = 0					            // limb 4
        eval.add_constraint(
            is_type_b.clone()
                * (op_c1_4.clone() * BaseField::from(2)
                    + op_c5_7.clone() * BaseField::from(1 << 5)
                    - value_c[0].clone()),
        );
        eval.add_constraint(
            is_type_b.clone()
                * (op_c8_10.clone()
                    + op_c11.clone() * BaseField::from(1 << 3)
                    + op_c12.clone() * BaseField::from((1 << 4) - 1) * BaseField::from(1 << 4)
                    - value_c[1].clone()),
        );
        eval.add_constraint(
            is_type_b.clone()
                * (op_c12.clone() * BaseField::from((1 << 8) - 1) - value_c[2].clone()),
        );
        eval.add_constraint(
            is_type_b.clone()
                * (op_c12.clone() * BaseField::from((1 << 8) - 1) - value_c[3].clone()),
        );

        let [op_a] = trace_eval!(trace_eval, Column::OpA);
        let [op_a0] = trace_eval!(trace_eval, Column::OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, Column::OpA1_4);

        // Making sure that op_a matches its parts
        // (is_type_b)・ (op_a0 + op_a1_4・2 – op_a) = 0
        eval.add_constraint(
            is_type_b.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a.clone()),
        );

        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        let [op_b0_3] = trace_eval!(trace_eval, Column::OpB0_3);
        let [op_b4] = trace_eval!(trace_eval, Column::OpB4);
        // Making sure that op_b matches its parts

        // (is_type_b)・ (op_b0_3 + op_b4・2^4 – op_b) = 0
        eval.add_constraint(
            is_type_b.clone()
                * (op_b0_3.clone() + op_b4.clone() * BaseField::from(1 << 4) - op_b.clone()),
        );

        let value_instr = trace_eval!(trace_eval, Column::InstrVal);
        // checking format of instructions - limb 1
        // (is_type_b) ・ (b1100011 + op_c11・2^7 - instr_val_1) = 0			// limb 1
        eval.add_constraint(
            is_type_b.clone()
                * (E::F::from(BaseField::from(0b1100011))
                    + op_c11.clone() * BaseField::from(1 << 7)
                    - value_instr[0].clone()),
        );

        let [is_beq] = trace_eval!(trace_eval, Column::IsBeq);
        let [is_bne] = trace_eval!(trace_eval, Column::IsBne);
        let [is_blt] = trace_eval!(trace_eval, Column::IsBlt);
        let [is_bge] = trace_eval!(trace_eval, Column::IsBge);
        let [is_bltu] = trace_eval!(trace_eval, Column::IsBltu);
        let [is_bgeu] = trace_eval!(trace_eval, Column::IsBgeu);

        // checking format of instructions - limb 2
        // (is_beq) ・ (op_c1_4 + b000・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - beq
        // (is_bne) ・ (op_c1_4 + b001・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - bne
        // (is_blt) ・ (op_c1_4 + b100・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - blt
        // (is_bge) ・ (op_c1_4 + b101・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - bge
        // (is_bltu)・ (op_c1_4 + b110・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - bltu
        // (is_bgeu)・ (op_c1_4 + b111・2^4 + op_a0・2^7 - instr_val_2) = 0 // limb 2 - bgeu

        eval.add_constraint(
            is_beq
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b000) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );

        eval.add_constraint(
            is_bne
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b001) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_blt
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b100) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_bge
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b101) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_bltu
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b110) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );
        eval.add_constraint(
            is_bgeu
                * (op_c1_4.clone()
                    + E::F::from(BaseField::from(0b111) * BaseField::from(1 << 4))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - value_instr[1].clone()),
        );

        // checking format of instructions - limb 3
        // (is_type_b) ・ (op_a1_4 + op_b0_3・2^4 - instr_val_3) = 0	// limb 3
        eval.add_constraint(
            is_type_b.clone()
                * (op_a1_4.clone() + op_b0_3.clone() * BaseField::from(1 << 4)
                    - value_instr[2].clone()),
        );

        let [op_b4] = trace_eval!(trace_eval, Column::OpB4);
        // checking format of instructions - limb 4
        // (is_type_b) ・ (op_b4 + op_c5_7・2 + op_c8_10・2^4 + op_c12・2^7 - instr_val_4) = 0 // limb 4
        eval.add_constraint(
            is_type_b.clone()
                * (op_b4
                    + op_c5_7.clone() * BaseField::from(2)
                    + op_c8_10.clone() * BaseField::from(1 << 4)
                    + op_c12.clone() * BaseField::from(1 << 7)
                    - value_instr[3].clone()),
        );
    }
}
