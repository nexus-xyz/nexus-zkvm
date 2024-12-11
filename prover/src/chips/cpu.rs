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
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, Traces,
    },
    traits::MachineChip,
};

use nexus_vm::riscv::{
    BuiltinOpcode,
    InstructionType::{BType, IType, ITypeShamt, JType, RType, SType, UType, Unimpl},
};

pub struct CpuChip;

impl MachineChip for CpuChip {
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        vm_step: &ProgramStep,
        _side_note: &mut SideNote,
    ) {
        let step = &vm_step.step;
        let pc = step.pc;
        // Sanity check: preprocessed column `Clk` contains `row_idx + 1`
        if !step.is_padding {
            debug_assert!(step.timestamp as usize == row_idx + 1);
        }

        // When row != 0 && pc == 0 are allowed
        // TODO: revise this 0th row check, see https://github.com/nexus-xyz/nexus-zkvm-neo/pull/145#discussion_r1842726498
        // assert!(!(row_idx == 0) || pc == 0);

        // Fill IsPadding row
        if step.is_padding {
            traces.fill_columns(row_idx, true, IsPadding);
        }

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
            Some(BuiltinOpcode::BGEU) => {
                traces.fill_columns(row_idx, true, IsBgeu);
            }
            _ => {
                if !step.is_padding {
                    panic!(
                        "Unsupported opcode: {:?}",
                        step.instruction.opcode.builtin()
                    );
                }
            }
        };

        traces.fill_columns(row_idx, pc, Pc);

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
        if !vm_step.step.is_padding {
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

        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = vm_step.value_a_effectitve_flag();
        traces.fill_columns(row_idx, value_a_effective_flag, ValueAEffectiveFlag);

        // Fill ValueAEffectiveFlagAux to the main trace
        // Note op_a is u8 so it is always smaller than M31.
        let value_a_effective_flag_aux = if op_a == 0 {
            BaseField::one()
        } else {
            BaseField::inverse(&BaseField::from(op_a as u32))
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
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        // TODO: add more constraints for the CPU chip.

        // Constrain IsPadding's range
        let ([is_padding], _) = trace_eval!(trace_eval, IsPadding);
        eval.add_constraint(is_padding.clone() * (E::F::one() - is_padding.clone()));

        // Padding rows should not access registers
        let ([is_padding], [next_is_padding]) = trace_eval!(trace_eval, Column::IsPadding);
        let ([reg1_accessed], _) = trace_eval!(trace_eval, Column::Reg1Accessed);
        let ([reg2_accessed], _) = trace_eval!(trace_eval, Column::Reg2Accessed);
        let ([reg3_accessed], _) = trace_eval!(trace_eval, Column::Reg3Accessed);
        eval.add_constraint(is_padding.clone() * reg1_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg2_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg3_accessed.clone());

        // Padding cannot go from 1 to zero, unless the current line is the first
        // TODO: consider forcing IsPadding == 0 on the first row, if we prefer to ban zero-step empty executions.
        let (_, [next_is_first]) =
            preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        eval.add_constraint(
            (E::F::one() - next_is_first.clone())
                * is_padding.clone()
                * (E::F::one() - next_is_padding.clone()),
        );

        // Constrain ValueAEffectiveFlag's range
        let ([value_a_effective_flag], _) = trace_eval!(trace_eval, ValueAEffectiveFlag);
        eval.add_constraint(
            value_a_effective_flag.clone() * (E::F::one() - value_a_effective_flag.clone()),
        );
        // TODO: relate OpA and ValueAEffectiveFlag; this can be done with ValueAEffectiveFlagAux and ValueAEffectiveFlagAuxInv.
        let ([value_a_effective_flag_aux], _) = trace_eval!(trace_eval, ValueAEffectiveFlagAux);
        let ([value_a_effective_flag_aux_inv], _) =
            trace_eval!(trace_eval, ValueAEffectiveFlagAuxInv);
        // Below is just for making sure value_a_effective_flag_aux is not zero.
        eval.add_constraint(
            value_a_effective_flag_aux.clone() * value_a_effective_flag_aux_inv - E::F::one(),
        );
        let ([op_a], _) = trace_eval!(trace_eval, OpA);
        // Since value_a_effective_flag_aux is non-zero, below means: op_a is zero if and only if value_a_effective_flag is zero.
        // Combined with value_a_effective_flag's range above, this determines value_a_effective_flag uniquely.
        eval.add_constraint(
            op_a.clone() * value_a_effective_flag_aux - value_a_effective_flag.clone(),
        );
        // Sum of IsOp flags is one. Combined with the range-checks in RangeBoolChip, the constraint implies exactly one of these flags is set.
        let ([is_add], _) = trace_eval!(trace_eval, IsAdd);
        let ([is_sub], _) = trace_eval!(trace_eval, IsSub);
        let ([is_and], _) = trace_eval!(trace_eval, IsAnd);
        let ([is_or], _) = trace_eval!(trace_eval, IsOr);
        let ([is_xor], _) = trace_eval!(trace_eval, IsXor);
        let ([is_slt], _) = trace_eval!(trace_eval, IsSlt);
        let ([is_sltu], _) = trace_eval!(trace_eval, IsSltu);
        let ([is_bne], _) = trace_eval!(trace_eval, IsBne);
        let ([is_beq], _) = trace_eval!(trace_eval, IsBeq);
        let ([is_bltu], _) = trace_eval!(trace_eval, IsBltu);
        let ([is_bgeu], _) = trace_eval!(trace_eval, IsBgeu);
        let ([is_padding], _) = trace_eval!(trace_eval, IsPadding);
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
                + is_padding
                - E::F::one(),
        );

        let ([imm_c], _) = trace_eval!(trace_eval, Column::ImmC);

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
        let ([reg1_accessed], _) = trace_eval!(trace_eval, Reg1Accessed);
        let ([reg2_accessed], _) = trace_eval!(trace_eval, Reg2Accessed);
        let ([reg3_accessed], _) = trace_eval!(trace_eval, Reg3Accessed);
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (E::F::one() - reg1_accessed.clone()),
        );
        eval.add_constraint(is_type_i.clone() * reg2_accessed.clone());
        eval.add_constraint(is_type_r.clone() * (E::F::one() - reg2_accessed.clone()));
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (E::F::one() - reg3_accessed.clone()),
        );

        // Constrain Reg{1,2,3}Address uniquely for type R and type I instructions
        let ([op_b], _) = trace_eval!(trace_eval, Column::OpB);
        let ([op_c], _) = trace_eval!(trace_eval, Column::OpC);
        let ([reg1_address], _) = trace_eval!(trace_eval, Column::Reg1Address);
        let ([reg2_address], _) = trace_eval!(trace_eval, Column::Reg2Address);
        let ([reg3_address], _) = trace_eval!(trace_eval, Column::Reg3Address);
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (op_b.clone() - reg1_address.clone()),
        );
        eval.add_constraint(is_type_r.clone() * (op_c.clone() - reg2_address));
        eval.add_constraint(is_type_i.clone() * op_c.clone());
        eval.add_constraint((is_type_r + is_type_i) * (op_a.clone() - reg3_address.clone()));

        // is_type_b = is_beq + is_bne + is_blt + is_bge + is_bltu + is_bgeu
        let is_type_b = is_beq + is_bne + is_bltu + is_bgeu; // TODO: add more flags when they are available

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
        eval.add_constraint(is_type_b_s * (op_a - reg3_address));
    }
}
