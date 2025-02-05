use crate::{
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::TraceEval, sidenote::SideNote, ProgramStep, TracesBuilder},
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use crate::column::Column::{
    self, ImmC, InstrVal, IsAdd, IsSub, OpA, OpA0, OpA1_4, OpB, OpB0, OpB1_4, OpC, OpC0_3, OpC4,
};
use crate::trace::eval::trace_eval;
use nexus_vm::riscv::InstructionType::RType;
use num_traits::One;
use stwo_prover::{constraint_framework::logup::LookupElements, core::fields::m31::BaseField};

pub struct TypeRChip;

impl MachineChip for TypeRChip {
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
        if step.instruction.ins_type != RType {
            return;
        }

        let op_a_raw = vm_step.step.instruction.op_a as u8;
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_a0, OpA0);
        traces.fill_columns(row_idx, op_a1_4, OpA1_4);

        let op_b_raw = vm_step.step.instruction.op_b as u8;
        let op_b0 = op_b_raw & 0x1;
        let op_b1_4 = (op_b_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_b0, OpB0);
        traces.fill_columns(row_idx, op_b1_4, OpB1_4);

        let op_c_raw = vm_step.step.instruction.op_c as u8;
        let op_c0_3 = op_c_raw & 0xF;
        let op_c4 = (op_c_raw >> 4) & 0x1;
        traces.fill_columns(row_idx, op_c0_3, OpC0_3);
        traces.fill_columns(row_idx, op_c4, OpC4);
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        // (is_type_r)・ (op_c0_3 + op_c4・2^4 – op_c) = 0
        let [is_type_r] = virtual_column::IsTypeR::eval(trace_eval);
        let [op_c0_3] = trace_eval!(trace_eval, OpC0_3);
        let [op_c4] = trace_eval!(trace_eval, OpC4);
        let [op_c] = trace_eval!(trace_eval, OpC);
        eval.add_constraint(
            is_type_r.clone() * (op_c0_3.clone() + op_c4.clone() * BaseField::from(1 << 4) - op_c),
        );

        // (is_type_r)・ (op_a0 + op_a1_4・2 – op_a) = 0
        let [op_a0] = trace_eval!(trace_eval, OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, OpA1_4);
        let [op_a] = trace_eval!(trace_eval, OpA);
        eval.add_constraint(
            is_type_r.clone() * (op_a0.clone() + op_a1_4.clone() * BaseField::from(1 << 1) - op_a),
        );

        // (is_type_r)・ (op_b0 + op_b1_4・2 – op_b) = 0
        let [op_b0] = trace_eval!(trace_eval, OpB0);
        let [op_b1_4] = trace_eval!(trace_eval, OpB1_4);
        let [op_b] = trace_eval!(trace_eval, OpB);
        eval.add_constraint(
            is_type_r.clone() * (op_b0.clone() + op_b1_4.clone() * BaseField::from(1 << 1) - op_b),
        );

        // (is_type_r) ・ (b0110011 + op_a0・2^7 - instr_val_1) = 0
        let instr_val = trace_eval!(trace_eval, InstrVal);
        eval.add_constraint(
            is_type_r.clone()
                * (E::F::from(BaseField::from(0b0110011))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - instr_val[0].clone()),
        );

        // (is_add) ・ (1-imm_c)・ (op_a1_4 + b000・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_add] = trace_eval!(trace_eval, IsAdd);
        let [imm_c] = trace_eval!(trace_eval, ImmC);
        let one = E::F::one();
        eval.add_constraint(
            is_add.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone() + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_sub) ・ (1-imm_c)・ (op_a1_4 + b000・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_sub] = trace_eval!(trace_eval, IsSub);
        eval.add_constraint(
            is_sub.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone() + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_sll) ・ (1-imm_c)・ (op_a1_4 + b001・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_sll] = trace_eval!(trace_eval, Column::IsSll);
        eval.add_constraint(
            is_sll.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b001)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_slt) ・ (1-imm_c)・ (op_a1_4 + b010・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_slt] = trace_eval!(trace_eval, Column::IsSlt);
        eval.add_constraint(
            is_slt.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b010)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_sltu)・ (1-imm_c)・ (op_a1_4 + b011・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_sltu] = trace_eval!(trace_eval, Column::IsSltu);
        eval.add_constraint(
            is_sltu.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b011)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_xor) ・ (1-imm_c)・ (op_a1_4 + b100・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_xor] = trace_eval!(trace_eval, Column::IsXor);
        eval.add_constraint(
            is_xor.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b100)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_srl) ・ (1-imm_c)・ (op_a1_4 + b101・24 + op_b0・27 - instr_val_2) = 0
        let [is_srl] = trace_eval!(trace_eval, Column::IsSrl);
        eval.add_constraint(
            is_srl.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b101)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_sra) ・ (1-imm_c)・ (op_a1_4 + b101・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_sra] = trace_eval!(trace_eval, Column::IsSra);
        eval.add_constraint(
            is_sra.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b101)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_or)  ・ (1-imm_c)・ (op_a1_4 + b110・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_or] = trace_eval!(trace_eval, Column::IsOr);
        eval.add_constraint(
            is_or.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b110)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_and) ・ (1-imm_c)・ (op_a1_4 + b111・2^4 + op_b0・2^7 - instr_val_2) = 0
        let [is_and] = trace_eval!(trace_eval, Column::IsAnd);
        eval.add_constraint(
            is_and.clone()
                * (one.clone() - imm_c.clone())
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b111)) * BaseField::from(1 << 4)
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val[1].clone()),
        );

        // (is_type_r) ・ (op_b1_4 + op_c0_3・2^4 - instr_val_3) = 0
        eval.add_constraint(
            is_type_r.clone()
                * (op_b1_4.clone() + op_c0_3.clone() * BaseField::from(1 << 4)
                    - instr_val[2].clone()),
        );

        // (is_add) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_add.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_sub) ・ (1-imm_c)・ (op_c4 + b0100000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_sub.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0100000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_sll) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_sll.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_slt) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_slt.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_sltu)・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_sltu.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_xor) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_xor.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_srl) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_srl.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_sra) ・ (1-imm_c)・ (op_c4 + b0100000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_sra.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0100000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_or)  ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_or.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );

        // (is_and) ・ (1-imm_c)・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_and.clone()
                * (one.clone() - imm_c.clone())
                * (op_c4.clone()
                    + E::F::from(BaseField::from(0b0000000)) * BaseField::from(1 << 1)
                    - instr_val[3].clone()),
        );
    }
}
