use num_traits::One;
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::fields::{m31::BaseField, FieldExpOps},
};

use crate::machine2::{
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
            Some(BuiltinOpcode::SLTU) => {
                traces.fill_columns(row_idx, true, IsSltu);
            }
            Some(BuiltinOpcode::SLT) | Some(BuiltinOpcode::SLTI) => {
                traces.fill_columns(row_idx, true, IsSlt);
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

        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = op_a != 0;
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
        let (_, [is_padding]) = trace_eval!(trace_eval, IsPadding);
        eval.add_constraint(is_padding.clone() * (E::F::one() - is_padding.clone()));

        // Padding rows should not access registers
        let ([prev_is_padding], [is_padding]) = trace_eval!(trace_eval, Column::IsPadding);
        let (_, [reg1_accessed]) = trace_eval!(trace_eval, Column::Reg1Accessed);
        let (_, [reg2_accessed]) = trace_eval!(trace_eval, Column::Reg2Accessed);
        let (_, [reg3_accessed]) = trace_eval!(trace_eval, Column::Reg3Accessed);
        eval.add_constraint(is_padding.clone() * reg1_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg2_accessed.clone());
        eval.add_constraint(is_padding.clone() * reg3_accessed.clone());

        // Padding cannot go from 1 to zero, unless the current line is the first
        // TODO: consider forcing IsPadding == 0 on the first row, if we prefer to ban zero-step empty executions.
        let (_, [is_first]) = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsFirst);
        eval.add_constraint(
            (E::F::one() - is_first.clone())
                * prev_is_padding.clone()
                * (E::F::one() - is_padding.clone()),
        );

        // Constrain ValueAEffectiveFlag's range
        let (_, [value_a_effective_flag]) = trace_eval!(trace_eval, ValueAEffectiveFlag);
        eval.add_constraint(
            value_a_effective_flag.clone() * (E::F::one() - value_a_effective_flag.clone()),
        );
        // TODO: relate OpA and ValueAEffectiveFlag; this can be done with ValueAEffectiveFlagAux and ValueAEffectiveFlagAuxInv.
        let (_, [value_a_effective_flag_aux]) = trace_eval!(trace_eval, ValueAEffectiveFlagAux);
        let (_, [value_a_effective_flag_aux_inv]) =
            trace_eval!(trace_eval, ValueAEffectiveFlagAuxInv);
        // Below is just for making sure value_a_effective_flag_aux is not zero.
        eval.add_constraint(
            value_a_effective_flag_aux.clone() * value_a_effective_flag_aux_inv - E::F::one(),
        );
        let (_, [op_a]) = trace_eval!(trace_eval, OpA);
        // Since value_a_effective_flag_aux is non-zero, below means: op_a is zero if and only if value_a_effective_flag is zero.
        // Combined with value_a_effective_flag's range above, this determines value_a_effective_flag uniquely.
        eval.add_constraint(op_a * value_a_effective_flag_aux - value_a_effective_flag.clone());
        // value_a_effective can be constrainted uniquely with value_a_effective_flag and value_a
        let (_, value_a) = trace_eval!(trace_eval, ValueA);
        let (_, value_a_effective) = trace_eval!(trace_eval, ValueAEffective);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                value_a_effective[i].clone() - value_a[i].clone() * value_a_effective_flag.clone(),
            );
        }
        // Sum of IsOp flags is one. Combined with the range-checks in RangeBoolChip, the constraint implies exactly one of these flags is set.
        let (_, [is_add]) = trace_eval!(trace_eval, IsAdd);
        let (_, [is_sub]) = trace_eval!(trace_eval, IsSub);
        let (_, [is_and]) = trace_eval!(trace_eval, IsAnd);
        let (_, [is_or]) = trace_eval!(trace_eval, IsOr);
        let (_, [is_slt]) = trace_eval!(trace_eval, IsSlt);
        let (_, [is_sltu]) = trace_eval!(trace_eval, IsSltu);
        let (_, [is_padding]) = trace_eval!(trace_eval, IsPadding);
        eval.add_constraint(
            is_add + is_sub + is_and + is_or + is_slt + is_sltu + is_padding - E::F::one(),
        );
    }
}
