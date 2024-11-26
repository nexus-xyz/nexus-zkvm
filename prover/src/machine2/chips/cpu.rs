use num_traits::One;
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::fields::{m31::BaseField, FieldExpOps as _},
};

use crate::machine2::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{trace_eval, TraceEval},
        regs::RegisterMemCheckSideNote,
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
        _side_note: &mut RegisterMemCheckSideNote,
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
        traces.fill_columns(row_idx, step.raw_instruction, InstructionWord);

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
    }
}
