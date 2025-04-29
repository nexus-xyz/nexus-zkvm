#![allow(clippy::identity_op)]

use stwo_prover::core::fields::m31::BaseField;

use crate::{
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{eval::TraceEval, sidenote::SideNote, ProgramStep, TracesBuilder},
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::riscv::InstructionType::{IType, ITypeShamt};

use crate::column::Column::{
    self, ImmC, InstrVal, IsAdd, IsAnd, IsJalr, IsLb, IsLbu, IsLh, IsLhu, IsLw, IsOr, IsSll, IsSlt,
    IsSltu, IsSra, IsSrl, IsXor, OpA, OpA0, OpA1_4, OpB, OpB0, OpB1_4, OpC, OpC0_3, OpC11, OpC4,
    OpC4_7, OpC8_10, ValueC,
};

use crate::trace::eval::trace_eval;

pub type TypeIChip = (TypeINoShiftChip, TypeIShiftChip);

pub struct TypeINoShiftChip;

impl MachineChip for TypeINoShiftChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step.as_ref().filter(|s| s.is_builtin()) {
            Some(vm_step) => vm_step,
            None => {
                return;
            }
        };
        let step = &vm_step.step;
        if step.instruction.ins_type != IType {
            return;
        }
        let op_a_raw = vm_step.step.instruction.op_a as u8;
        let op_b_raw = vm_step.step.instruction.op_b as u8;
        let op_c_raw = vm_step.step.instruction.op_c;

        // Fill auxiliary columns for type I immediate value parsing
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_a0, OpA0);
        traces.fill_columns(row_idx, op_a1_4, OpA1_4);

        let op_b0 = op_b_raw & 0x1;
        let op_b1_4 = (op_b_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_b0, OpB0);
        traces.fill_columns(row_idx, op_b1_4, OpB1_4);

        let op_c0_3 = op_c_raw & 0xF;
        let op_c4_7 = (op_c_raw >> 4) & 0xF;
        let op_c8_10 = (op_c_raw >> 8) & 0x7;
        let op_c11 = (op_c_raw >> 11) & 0x1;
        traces.fill_columns(row_idx, op_c0_3 as u8, OpC0_3);
        traces.fill_columns(row_idx, op_c4_7 as u8, OpC4_7);
        traces.fill_columns(row_idx, op_c8_10 as u8, OpC8_10);
        traces.fill_columns(row_idx, op_c11 as u8, OpC11);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_type_i_no_shift] = virtual_column::IsTypeINoShift::eval(trace_eval);
        let [op_c0_3] = trace_eval!(trace_eval, OpC0_3);
        let [op_c4_7] = trace_eval!(trace_eval, OpC4_7);
        let [op_c8_10] = trace_eval!(trace_eval, OpC8_10);
        let [op_c11] = trace_eval!(trace_eval, OpC11);
        let [op_c] = trace_eval!(trace_eval, OpC);
        let value_c = trace_eval!(trace_eval, ValueC);

        // (is_type_i_no_shift)・ (op_c0_3 + op_c4_7・2^4 + op_c8_10・2^8 + op_c11・2^11 – op_c) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_c0_3.clone()
                    + op_c4_7.clone() * BaseField::from(1 << 4)
                    + op_c8_10.clone() * BaseField::from(1 << 8)
                    + op_c11.clone() * BaseField::from(1 << 11)
                    - op_c.clone()),
        );

        // (is_type_i_no_shift)・(op_c0_3 + op_c4_7・2^4 – c_val_1) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_c0_3.clone() + op_c4_7.clone() * BaseField::from(1 << 4)
                    - value_c[0].clone()),
        );
        // (is_type_i_no_shift)・(op_c8_10 + op_c11・(2^5-1)·2^3 – c_val_2) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_c8_10.clone()
                    + op_c11.clone() * BaseField::from((2u32.pow(5) - 1) * 2u32.pow(3))
                    - value_c[1].clone()),
        );
        // (is_type_i_no_shift)・(op_c11・(2^8-1) – c_val_3) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - value_c[2].clone()),
        );
        // (is_type_i_no_shift)・(op_c11・(2^8-1) – c_val_4) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_c11.clone() * BaseField::from((1 << 8) - 1) - value_c[3].clone()),
        );

        let [op_a] = trace_eval!(trace_eval, OpA);
        let [op_a0] = trace_eval!(trace_eval, OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, OpA1_4);

        // is_type_i_no_shift・(op_a0 + op_a1_4・2 – op_a) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a),
        );

        let [op_b] = trace_eval!(trace_eval, OpB);
        let [op_b0] = trace_eval!(trace_eval, OpB0);
        let [op_b1_4] = trace_eval!(trace_eval, OpB1_4);
        // is_type_i_no_shift・(op_b0 + op_b1_4・2 – op_b) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_b0.clone() + op_b1_4.clone() * BaseField::from(2) - op_b),
        );

        // instructions constraints
        let [instr_val_1, instr_val_2, instr_val_3, instr_val_4] =
            trace_eval!(trace_eval, InstrVal);
        let [is_jalr] = trace_eval!(trace_eval, IsJalr);
        let [is_load] = virtual_column::IsLoad::eval(trace_eval);
        let [is_lb] = trace_eval!(trace_eval, IsLb);
        let [is_lh] = trace_eval!(trace_eval, IsLh);
        let [is_lw] = trace_eval!(trace_eval, IsLw);
        let [is_lbu] = trace_eval!(trace_eval, IsLbu);
        let [is_lhu] = trace_eval!(trace_eval, IsLhu);
        let [is_alu_imm_no_shift] = virtual_column::IsAluImmNoShift::eval(trace_eval);

        // (is_load)・(b0000011 + op_a0・2^7 - instr_val_1) = 0
        eval.add_constraint(
            is_load
                * (E::F::from(BaseField::from(0b0000011))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - instr_val_1.clone()),
        );
        // (is_alu_imm_no_shift)・(b0010011 + op_a0・2^7 - instr_val_1) = 0
        eval.add_constraint(
            is_alu_imm_no_shift
                * (E::F::from(BaseField::from(0b0010011))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - instr_val_1.clone()),
        );
        // (is_jalr) ・(b1100111 + op_a0・2^7 - instr_val_1) = 0
        eval.add_constraint(
            is_jalr.clone()
                * (E::F::from(BaseField::from(0b1100111)) + op_a0 * BaseField::from(1 << 7)
                    - instr_val_1),
        );
        // (is_lb)・(op_a1_4 + b000・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_lb
                * (op_a1_4.clone() + op_b0.clone() * BaseField::from(1 << 7) - instr_val_2.clone()),
        );
        // (is_lh)・(op_a1_4 + b001・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_lh
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b001 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_lw)・(op_a1_4 + b010・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_lw
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b010 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_lbu)・(op_a1_4 + b100・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_lbu
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b100 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_lhu)・(op_a1_4 + b101・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_lhu
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b101 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );

        let [imm_c] = trace_eval!(trace_eval, ImmC);
        let [is_add] = trace_eval!(trace_eval, IsAdd);
        let [is_slt] = trace_eval!(trace_eval, IsSlt);
        let [is_sltu] = trace_eval!(trace_eval, IsSltu);
        let [is_xor] = trace_eval!(trace_eval, IsXor);
        let [is_or] = trace_eval!(trace_eval, IsOr);
        let [is_and] = trace_eval!(trace_eval, IsAnd);

        // (is_add)・imm_c・(op_a1_4 + b000・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_add
                * imm_c.clone()
                * (op_a1_4.clone() + op_b0.clone() * BaseField::from(1 << 7) - instr_val_2.clone()),
        );
        // (is_slt)・imm_c・(op_a1_4 + b010・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_slt
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b010 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_sltu)・imm_c・(op_a1_4 + b011・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_sltu
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b011 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_xor)・imm_c・(op_a1_4 + b100・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_xor
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b100 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_or)・imm_c・(op_a1_4 + b110・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_or
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b110 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_and)・imm_c・(op_a1_4 + b111・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_and
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b111 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_jalr)・(op_a1_4 + b000・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_jalr
                * (op_a1_4.clone() + op_b0.clone() * BaseField::from(1 << 7) - instr_val_2.clone()),
        );

        // (is_type_i_no_shift)・(op_b1_4 + op_c0_3・2^4 - instr_val_3) = 0
        eval.add_constraint(
            is_type_i_no_shift.clone()
                * (op_b1_4.clone() + op_c0_3.clone() * BaseField::from(1 << 4) - instr_val_3),
        );
        // (is_type_i_no_shift)・(op_c4_7 + op_c8_10・2^4 + op_c11・2^7 - instr_val_4) = 0
        eval.add_constraint(
            is_type_i_no_shift
                * (op_c4_7 + op_c8_10 * BaseField::from(1 << 4) + op_c11 * BaseField::from(1 << 7)
                    - instr_val_4),
        );
    }
}

pub struct TypeIShiftChip;

impl MachineChip for TypeIShiftChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step.as_ref().filter(|s| s.is_builtin()) {
            Some(vm_step) => vm_step,
            None => {
                return;
            }
        };
        let step = &vm_step.step;
        if step.instruction.ins_type != ITypeShamt {
            return;
        }

        let op_a_raw = vm_step.step.instruction.op_a as u8;
        let op_b_raw = vm_step.step.instruction.op_b as u8;
        let op_c_raw = vm_step.step.instruction.op_c;

        // Fill auxiliary columns for type I immediate value parsing
        let op_a0 = op_a_raw & 0x1;
        let op_a1_4 = (op_a_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_a0, OpA0);
        traces.fill_columns(row_idx, op_a1_4, OpA1_4);

        let op_b0 = op_b_raw & 0x1;
        let op_b1_4 = (op_b_raw >> 1) & 0xF;
        traces.fill_columns(row_idx, op_b0, OpB0);
        traces.fill_columns(row_idx, op_b1_4, OpB1_4);

        let op_c0_3 = op_c_raw & 0xF;
        let op_c4 = (op_c_raw >> 4) & 0x1;
        traces.fill_columns(row_idx, op_c0_3 as u8, OpC0_3);
        traces.fill_columns(row_idx, op_c4 as u8, OpC4);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        let [is_alu_imm_shift] = virtual_column::IsAluImmShift::eval(trace_eval);
        let [op_c0_3] = trace_eval!(trace_eval, OpC0_3);
        let [op_c4] = trace_eval!(trace_eval, OpC4);
        let [op_c] = trace_eval!(trace_eval, OpC);

        // (is_alu_imm_shift)・(op_c0_3 + op_c4・2^4 – op_c) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (op_c0_3.clone() + op_c4.clone() * BaseField::from(1 << 4) - op_c.clone()),
        );

        // constrain value c
        let value_c = trace_eval!(trace_eval, ValueC);

        // (is_alu_imm_shift)・(op_c0_3 + op_c4・2^4 – c_val_1) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (op_c0_3.clone() + op_c4.clone() * BaseField::from(1 << 4) - value_c[0].clone()),
        );
        // (is_alu_imm_shift)・(c_val_2) = 0
        eval.add_constraint(is_alu_imm_shift.clone() * (value_c[1].clone()));
        // (is_alu_imm_shift)・(c_val_3) = 0
        eval.add_constraint(is_alu_imm_shift.clone() * (value_c[2].clone()));
        // (is_alu_imm_shift)・(c_val_4) = 0
        eval.add_constraint(is_alu_imm_shift.clone() * (value_c[3].clone()));

        // constrain op_a
        let [op_a] = trace_eval!(trace_eval, OpA);
        let [op_a0] = trace_eval!(trace_eval, OpA0);
        let [op_a1_4] = trace_eval!(trace_eval, OpA1_4);

        // is_alu_imm_shift・(op_a0 + op_a1_4・2 – op_a) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (op_a0.clone() + op_a1_4.clone() * BaseField::from(2) - op_a.clone()),
        );

        // constrain op_b
        let [op_b] = trace_eval!(trace_eval, OpB);
        let [op_b0] = trace_eval!(trace_eval, OpB0);
        let [op_b1_4] = trace_eval!(trace_eval, OpB1_4);

        // is_alu_imm_shift・(op_b0 + op_b1_4・2 – op_b) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (op_b0.clone() + op_b1_4.clone() * BaseField::from(2) - op_b.clone()),
        );

        // instructions constraints
        let [instr_val_1, instr_val_2, instr_val_3, instr_val_4] =
            trace_eval!(trace_eval, InstrVal);
        let [is_sll] = trace_eval!(trace_eval, IsSll);
        let [is_srl] = trace_eval!(trace_eval, IsSrl);
        let [is_sra] = trace_eval!(trace_eval, IsSra);
        let [imm_c] = trace_eval!(trace_eval, ImmC);
        // (is_alu_imm_shift) ・(b0010011 + op_a0・2^7 - instr_val_1) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (E::F::from(BaseField::from(0b0010011))
                    + op_a0.clone() * BaseField::from(1 << 7)
                    - instr_val_1.clone()),
        );
        // (is_sll)・imm_c・ (op_a1_4 + b001・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_sll.clone()
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b001 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_srl)・imm_c・(op_a1_4 + b101・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_srl.clone()
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b101 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );
        // (is_sra)・imm_c・(op_a1_4 + b101・2^4 + op_b0・2^7 - instr_val_2) = 0
        eval.add_constraint(
            is_sra.clone()
                * imm_c.clone()
                * (op_a1_4.clone()
                    + E::F::from(BaseField::from(0b101 * 2u32.pow(4)))
                    + op_b0.clone() * BaseField::from(1 << 7)
                    - instr_val_2.clone()),
        );

        // (is_alu_imm_shift)・(op_b1_4 + op_c0_3・2^4 - instr_val_3) = 0
        eval.add_constraint(
            is_alu_imm_shift.clone()
                * (op_b1_4.clone() + op_c0_3.clone() * BaseField::from(1 << 4)
                    - instr_val_3.clone()),
        );
        // (is_sll)・imm_c・ (op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(is_sll * imm_c.clone() * (op_c4.clone() - instr_val_4.clone()));
        // (is_srl)・imm_c・(op_c4 + b0000000・2 - instr_val_4) = 0
        eval.add_constraint(is_srl * imm_c.clone() * (op_c4.clone() - instr_val_4.clone()));
        // (is_sra)・imm_c・(op_c4 + b0100000・2 - instr_val_4) = 0
        eval.add_constraint(
            is_sra
                * imm_c.clone()
                * (op_c4.clone() + E::F::from(BaseField::from(0b0100000 * 2))
                    - instr_val_4.clone()),
        );
    }
}
