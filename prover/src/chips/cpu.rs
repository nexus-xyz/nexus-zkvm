use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::fields::{m31::BaseField, FieldExpOps},
};

use crate::{
    column::{
        Column::{self, *},
        PreprocessedColumn,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval_next_row, trace_eval, trace_eval_next_row, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        ProgramStep, Traces,
    },
    traits::MachineChip,
};

use nexus_vm::{
    riscv::{
        BuiltinOpcode,
        InstructionType::{BType, IType, ITypeShamt, JType, RType, SType, UType, Unimpl},
    },
    WORD_SIZE,
};

pub struct CpuChip;

impl MachineChip for CpuChip {
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _program_traces: &ProgramTraces,
        _side_note: &mut SideNote,
    ) {
        // When row != 0 && pc == 0 are allowed
        // TODO: revise this 0th row check, see https://github.com/nexus-xyz/nexus-zkvm-neo/pull/145#discussion_r1842726498
        // assert!(!(row_idx == 0) || pc == 0);

        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = match vm_step {
            Some(vm_step) => vm_step.value_a_effectitve_flag(),
            None => false,
        };
        traces.fill_columns(row_idx, value_a_effective_flag, ValueAEffectiveFlag);

        // Fill ValueAEffectiveFlagAux to the main trace
        // Note op_a is u8 so it is always smaller than M31.
        let value_a_effective_flag_aux = if let Some(vm_step) = vm_step {
            let op_a = vm_step.step.instruction.op_a as u8;
            if op_a == 0 {
                BaseField::one()
            } else {
                BaseField::inverse(&BaseField::from(op_a as u32))
            }
        } else {
            BaseField::one()
        };

        traces.fill_columns_basefield(
            row_idx,
            &[value_a_effective_flag_aux],
            ValueAEffectiveFlagAux,
        );

        // Fill ValueAEffectiveFlagAuxInv to the main trace
        let value_a_effective_flag_aux_inv = BaseField::inverse(&value_a_effective_flag_aux);
        traces.fill_columns_basefield(
            row_idx,
            &[value_a_effective_flag_aux_inv],
            ValueAEffectiveFlagAuxInv,
        );

        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => {
                // padding
                traces.fill_columns(row_idx, true, IsPadding);
                return;
            }
        };

        let step = &vm_step.step;
        let pc = step.pc;
        // Sanity check: preprocessed column `Clk` contains `row_idx + 1`
        assert!(step.timestamp as usize == row_idx + 1);
        traces.fill_columns(row_idx, pc, Pc);

        // Add opcode to the main trace
        // TODO: We should also set ImmC or ImmB flags here.
        // Set is_opcode to 1, e.g If this is ADD opcode, set IsAdd to 1.
        match step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI) => {
                traces.fill_columns(row_idx, true, IsAdd);
            }
            Some(BuiltinOpcode::AND) | Some(BuiltinOpcode::ANDI) => {
                traces.fill_columns(row_idx, true, IsAnd);
            }
            Some(BuiltinOpcode::OR) | Some(BuiltinOpcode::ORI) => {
                traces.fill_columns(row_idx, true, IsOr);
            }
            Some(BuiltinOpcode::XOR) | Some(BuiltinOpcode::XORI) => {
                traces.fill_columns(row_idx, true, IsXor);
            }
            Some(BuiltinOpcode::SUB) => {
                traces.fill_columns(row_idx, true, IsSub);
            }
            Some(BuiltinOpcode::SLTU) | Some(BuiltinOpcode::SLTIU) => {
                traces.fill_columns(row_idx, true, IsSltu);
            }
            Some(BuiltinOpcode::SLT) | Some(BuiltinOpcode::SLTI) => {
                traces.fill_columns(row_idx, true, IsSlt);
            }
            Some(BuiltinOpcode::BNE) => {
                traces.fill_columns(row_idx, true, IsBne);
            }
            Some(BuiltinOpcode::BEQ) => {
                traces.fill_columns(row_idx, true, IsBeq);
            }
            Some(BuiltinOpcode::BLTU) => {
                traces.fill_columns(row_idx, true, IsBltu);
            }
            Some(BuiltinOpcode::BLT) => {
                traces.fill_columns(row_idx, true, IsBlt);
            }
            Some(BuiltinOpcode::BGEU) => {
                traces.fill_columns(row_idx, true, IsBgeu);
            }
            Some(BuiltinOpcode::BGE) => {
                traces.fill_columns(row_idx, true, IsBge);
            }
            Some(BuiltinOpcode::JAL) => {
                traces.fill_columns(row_idx, true, IsJal);
            }
            _ => {
                panic!(
                    "Unsupported opcode: {:?}",
                    step.instruction.opcode.builtin()
                );
            }
        }
        traces.fill_columns(row_idx, pc.wrapping_add(WORD_SIZE as u32), PcNext); // default expectation of the next Pc; might be overwritten by Branch or Jump chips

        // Fill ValueB and ValueC to the main trace
        traces.fill_columns(row_idx, vm_step.get_value_b(), ValueB);

        traces.fill_columns(row_idx, vm_step.get_value_c(), ValueC);

        // Fill InstructionWord to the main trace
        traces.fill_columns(row_idx, step.raw_instruction, InstrVal);

        // Fill OpA to the main trace
        let op_a = vm_step.step.instruction.op_a as u8;
        traces.fill_columns(row_idx, op_a, OpA);

        // Fill OpB to the main trace
        let op_b = vm_step.step.instruction.op_b as u8;
        traces.fill_columns(row_idx, op_b, OpB);
        // Fill OpC (if register index) or ImmC (if immediate) to the main trace
        let op_c_raw = vm_step.step.instruction.op_c;
        match vm_step.step.instruction.ins_type {
            RType => {
                traces.fill_columns(row_idx, op_c_raw as u8, OpC);
            }
            IType | BType | SType | ITypeShamt | JType | UType => {
                traces.fill_columns(row_idx, true, ImmC); // ImmC is a boolean flag
            }
            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }

        // Fill register access flags in the main trace
        // We use Reg3 for the destination because Reg{1,2,3} have to be accessed in this order.
        match vm_step.step.instruction.ins_type {
            RType => {
                traces.fill_columns(row_idx, true, Reg1Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_b as u8, Reg1Address);
                traces.fill_columns(row_idx, true, Reg2Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_c as u8, Reg2Address);
                traces.fill_columns(row_idx, true, Reg3Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            IType | ITypeShamt => {
                traces.fill_columns(row_idx, true, Reg1Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_b as u8, Reg1Address);
                traces.fill_columns(row_idx, true, Reg3Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            UType => {
                traces.fill_columns(row_idx, true, Reg3Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            BType | SType => {
                traces.fill_columns(row_idx, true, Reg1Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_b as u8, Reg1Address);
                traces.fill_columns(row_idx, true, Reg3Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            JType => {
                traces.fill_columns(row_idx, true, Reg3Accessed);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        // TODO: add more constraints for the CPU chip.

        // Constrain IsPadding's range
        let [is_padding] = trace_eval!(trace_eval, IsPadding);
        eval.add_constraint(is_padding.clone() * (E::F::one() - is_padding.clone()));

        // Padding rows should not access registers
        let [next_is_padding] = trace_eval_next_row!(trace_eval, Column::IsPadding);
        let [reg1_accessed] = trace_eval!(trace_eval, Column::Reg1Accessed);
        let [reg2_accessed] = trace_eval!(trace_eval, Column::Reg2Accessed);
        let [reg3_accessed] = trace_eval!(trace_eval, Column::Reg3Accessed);
        eval.add_constraint(is_padding.clone() * reg1_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg2_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg3_accessed.clone());

        // Padding cannot go from 1 to zero, unless the current line is the first
        // TODO: consider forcing IsPadding == 0 on the first row, if we prefer to ban zero-step empty executions.
        let [next_is_first] =
            preprocessed_trace_eval_next_row!(trace_eval, PreprocessedColumn::IsFirst);
        eval.add_constraint(
            (E::F::one() - next_is_first.clone())
                * is_padding.clone()
                * (E::F::one() - next_is_padding.clone()),
        );

        // Constrain ValueAEffectiveFlag's range
        let [value_a_effective_flag] = trace_eval!(trace_eval, ValueAEffectiveFlag);
        eval.add_constraint(
            value_a_effective_flag.clone() * (E::F::one() - value_a_effective_flag.clone()),
        );
        // TODO: relate OpA and ValueAEffectiveFlag; this can be done with ValueAEffectiveFlagAux and ValueAEffectiveFlagAuxInv.
        let [value_a_effective_flag_aux] = trace_eval!(trace_eval, ValueAEffectiveFlagAux);
        let [value_a_effective_flag_aux_inv] = trace_eval!(trace_eval, ValueAEffectiveFlagAuxInv);
        // Below is just for making sure value_a_effective_flag_aux is not zero.
        eval.add_constraint(
            value_a_effective_flag_aux.clone() * value_a_effective_flag_aux_inv - E::F::one(),
        );
        let [op_a] = trace_eval!(trace_eval, OpA);
        // Since value_a_effective_flag_aux is non-zero, below means: op_a is zero if and only if value_a_effective_flag is zero.
        // Combined with value_a_effective_flag's range above, this determines value_a_effective_flag uniquely.
        eval.add_constraint(
            op_a.clone() * value_a_effective_flag_aux - value_a_effective_flag.clone(),
        );
        // Sum of IsOp flags is one. Combined with the range-checks in RangeBoolChip, the constraint implies exactly one of these flags is set.
        let [is_add] = trace_eval!(trace_eval, IsAdd);
        let [is_sub] = trace_eval!(trace_eval, IsSub);
        let [is_and] = trace_eval!(trace_eval, IsAnd);
        let [is_or] = trace_eval!(trace_eval, IsOr);
        let [is_xor] = trace_eval!(trace_eval, IsXor);
        let [is_slt] = trace_eval!(trace_eval, IsSlt);
        let [is_sltu] = trace_eval!(trace_eval, IsSltu);
        let [is_bne] = trace_eval!(trace_eval, IsBne);
        let [is_beq] = trace_eval!(trace_eval, IsBeq);
        let [is_bltu] = trace_eval!(trace_eval, IsBltu);
        let [is_blt] = trace_eval!(trace_eval, IsBlt);
        let [is_bgeu] = trace_eval!(trace_eval, IsBgeu);
        let [is_bge] = trace_eval!(trace_eval, IsBge);
        let [is_jal] = trace_eval!(trace_eval, IsJal);
        let [is_padding] = trace_eval!(trace_eval, IsPadding);
        eval.add_constraint(
            is_add.clone()
                + is_sub.clone()
                + is_and.clone()
                + is_or.clone()
                + is_xor.clone()
                + is_slt.clone()
                + is_sltu.clone()
                + is_bne.clone()
                + is_beq.clone()
                + is_bltu.clone()
                + is_bgeu.clone()
                + is_blt.clone()
                + is_bge.clone()
                + is_jal.clone()
                + is_padding
                - E::F::one(),
        );

        let [imm_c] = trace_eval!(trace_eval, Column::ImmC);

        // is_type_r = (1-imm_c) ・(is_add + is_sub + is_slt + is_sltu + is_xor + is_or + is_and + is_sll + is_srl + is_sra)
        let is_type_r = (E::F::one() - imm_c.clone())
            * (is_add.clone()
                + is_sub.clone()
                + is_slt.clone()
                + is_sltu.clone()
                + is_xor.clone()
                + is_or.clone()
                + is_and.clone());

        // is_alu_imm_no_shift = imm_c・(is_add + is_slt + is_sltu + is_xor + is_or + is_and)
        let is_alu_imm_no_shift =
            imm_c.clone() * (is_add + is_slt + is_sltu + is_xor + is_or + is_and);

        // is_type_i = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift
        let is_type_i = is_alu_imm_no_shift; // TODO: Add more flags when they are available

        // Constrain Reg{1,2,3}Accessed for type R and type I instructions
        let [reg1_accessed] = trace_eval!(trace_eval, Reg1Accessed);
        let [reg2_accessed] = trace_eval!(trace_eval, Reg2Accessed);
        let [reg3_accessed] = trace_eval!(trace_eval, Reg3Accessed);
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (E::F::one() - reg1_accessed.clone()),
        );
        eval.add_constraint(is_type_i.clone() * reg2_accessed.clone());
        eval.add_constraint(is_type_r.clone() * (E::F::one() - reg2_accessed.clone()));
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (E::F::one() - reg3_accessed.clone()),
        );

        // Constrain Reg{1,2,3}Address uniquely for type R and type I instructions
        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);
        let [reg1_address] = trace_eval!(trace_eval, Column::Reg1Address);
        let [reg2_address] = trace_eval!(trace_eval, Column::Reg2Address);
        let [reg3_address] = trace_eval!(trace_eval, Column::Reg3Address);
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (op_b.clone() - reg1_address.clone()),
        );
        eval.add_constraint(is_type_r.clone() * (op_c.clone() - reg2_address));
        eval.add_constraint(is_type_i.clone() * op_c.clone());
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (op_a.clone() - reg3_address.clone()),
        );

        // Constrain read access doesn't change register values for type R and type I instructions
        let reg1_val_prev = trace_eval!(trace_eval, Column::Reg1ValPrev);
        let reg2_val_prev = trace_eval!(trace_eval, Column::Reg2ValPrev);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                (is_type_r.clone() + is_type_i.clone())
                    * (reg1_val_prev[limb_idx].clone() - value_b[limb_idx].clone()),
            );
            eval.add_constraint(
                is_type_r.clone() * (reg2_val_prev[limb_idx].clone() - value_c[limb_idx].clone()),
            );
        }

        // is_type_b = is_beq + is_bne + is_blt + is_bge + is_bltu + is_bgeu
        let is_type_b = is_beq + is_bne + is_bltu + is_bgeu + is_blt + is_bge;

        // is_type_s = is_sb + is_sh + is_sw
        // TODO: define is_type_s when flags are available
        let is_type_s = E::F::zero();

        // type S and type B access registers in similar ways
        let is_type_b_s = is_type_b + is_type_s;

        // Constrain reg{1,2,3}_accessed for type B and type S instructions
        eval.add_constraint((is_type_b_s.clone()) * (E::F::one() - reg1_accessed.clone()));
        eval.add_constraint(is_type_b_s.clone() * reg2_accessed.clone());
        eval.add_constraint((is_type_b_s.clone()) * (E::F::one() - reg3_accessed.clone()));

        // Constraint reg{1,2,3}_address uniquely for type B and type S instructions
        eval.add_constraint(is_type_b_s.clone() * (op_b - reg1_address));
        eval.add_constraint(is_type_b_s.clone() * op_c);
        // Always using reg3 for ValueA and OpA, even when it's not the destination; this simplifies the register memory checking.
        eval.add_constraint(is_type_b_s.clone() * (op_a - reg3_address));

        let reg3_val_prev = trace_eval!(trace_eval, Column::Reg3ValPrev);
        let value_a = trace_eval!(trace_eval, Column::ValueA);

        // Constrain read access doesn't change register values for type B and type S instructions
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                is_type_b_s.clone() * (reg1_val_prev[limb_idx].clone() - value_b[limb_idx].clone()),
            );
            eval.add_constraint(
                is_type_b_s.clone() * (reg3_val_prev[limb_idx].clone() - value_a[limb_idx].clone()),
            );
        }

        // PcNext should be Pc on the next row, unless the next row is the first row or padding.
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let pc_on_next_row = trace_eval_next_row!(trace_eval, Column::Pc);
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                (E::F::one() - next_is_first.clone())
                    * (E::F::one() - next_is_padding.clone())
                    * (pc_next[limb_idx].clone() - pc_on_next_row[limb_idx].clone()),
            );
        }
    }
}
