use num_traits::One;
use stwo_prover::constraint_framework::{logup::LookupElements, EvalAtRow};

use crate::machine2::{
    column::Column::{self, *},
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{eval::trace_eval, eval::TraceEval, ProgramStep, Traces},
    traits::MachineChip,
};

use nexus_vm::riscv::{
    BuiltinOpcode,
    InstructionType::{BType, IType, ITypeShamt, JType, RType, SType, UType, Unimpl},
};

pub struct CpuChip;

impl MachineChip for CpuChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        let step = &vm_step.step;
        let pc = step.pc;
        // Sanity check: preprocessed column `Clk` contains `row_idx + 1`
        debug_assert!(step.timestamp as usize == row_idx + 1);

        // When row != 0 && pc == 0 are allowed
        // TODO: revise this 0th row check, see https://github.com/nexus-xyz/nexus-zkvm-neo/pull/145#discussion_r1842726498
        // assert!(!(row_idx == 0) || pc == 0);

        // Add opcode to the main trace
        // TODO: We should also set ImmC or ImmB flags here.
        // Set is_opcode to 1, e.g If this is ADD opcode, set IsAdd to 1.
        match step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI) => {
                traces.fill_columns(row_idx, &[1], IsAdd);
            }
            Some(BuiltinOpcode::SUB) => {
                traces.fill_columns(row_idx, &[1], IsSub);
            }
            Some(BuiltinOpcode::SLTU) => {
                traces.fill_columns(row_idx, &[1], IsSltu);
            }
            _ => panic!(
                "Unsupported opcode: {:?}",
                step.instruction.opcode.builtin()
            ),
        };

        let pc_bytes = pc.to_le_bytes();
        traces.fill_columns(row_idx, &pc_bytes, Pc);

        // Fill ValueB and ValueC to the main trace
        let value_b = vm_step.get_value_b();
        traces.fill_columns(row_idx, &value_b, ValueB);

        let (value_c, _effective_size) = vm_step.get_value_c();
        traces.fill_columns(row_idx, &value_c, ValueC);

        // Fill InstructionWord to the main trace
        let instruction_word = step.raw_instruction.to_le_bytes();
        traces.fill_columns(row_idx, &instruction_word, InstructionWord);

        // Fill OpA to the main trace
        let op_a = vm_step.step.instruction.op_a as u8;
        traces.fill_columns(row_idx, &[op_a], OpA);

        // Fill OpB to the main trace
        let op_b = vm_step.step.instruction.op_b as u8;
        traces.fill_columns(row_idx, &[op_b], OpB);

        // Fill OpC (if register index) or ImmC (if immediate) to the main trace
        let op_c_raw = vm_step.step.instruction.op_c;
        match vm_step.step.instruction.ins_type {
            RType => {
                traces.fill_columns(row_idx, &[op_c_raw as u8], OpC);
            }
            IType | BType | SType | ITypeShamt | JType | UType => {
                traces.fill_columns(row_idx, &[1], ImmC); // ImmC is a boolean flag
            }
            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }

        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = if op_a == 0 { 0 } else { 1 };
        traces.fill_columns(row_idx, &[value_a_effective_flag], ValueAEffectiveFlag);
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
            value_a_effective_flag.clone() * (E::F::one() - value_a_effective_flag),
        );
        // TODO: relate OpA and ValueAEffectiveFlag; this can be done with ValueAEffectiveFlagAux and ValueAEffectiveFlagAuxInv.
    }
}
