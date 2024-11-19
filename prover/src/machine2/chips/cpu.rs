use num_traits::One;
use stwo_prover::constraint_framework::EvalAtRow;

use crate::machine2::{
    column::Column::{self, *},
    trace::{eval::trace_eval, eval::TraceEval, ProgramStep, Traces},
    traits::MachineChip,
};

use nexus_vm::riscv::BuiltinOpcode;

pub struct CpuChip;

impl MachineChip for CpuChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &ProgramStep) {
        let step = &vm_step.step;
        let pc = step.pc;
        let timestamp = step.timestamp;
        let clk = timestamp;

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

        let clk_bytes = clk.to_le_bytes();
        traces.fill_columns(row_idx, &clk_bytes, Clk);

        // Fill ValueB and ValueC to the main trace
        let value_b = vm_step.get_value_b();
        traces.fill_columns(row_idx, &value_b, ValueB);

        let (value_c, _effective_size) = vm_step.get_value_c();
        traces.fill_columns(row_idx, &value_c, ValueC);

        // Fill OpA to the main trace
        let op_a = vm_step.step.instruction.op_a as u8;
        traces.fill_columns(row_idx, &[op_a], OpA);

        // Fill OpB to the main trace
        let op_b = vm_step.step.instruction.op_b as u8;
        traces.fill_columns(row_idx, &[op_b], OpB);

        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = if op_a == 0 { 0 } else { 1 };
        traces.fill_columns(row_idx, &[value_a_effective_flag], ValueAEffectiveFlag);
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        // TODO: add more constraints for the CPU chip.

        // Constrain ValueAEffectiveFlag's range
        let (_, [value_a_effective_flag]) = trace_eval!(trace_eval, ValueAEffectiveFlag);
        eval.add_constraint(
            value_a_effective_flag.clone() * (E::F::one() - value_a_effective_flag),
        );
        // TODO: relate OpA and ValueAEffectiveFlag; this can be done with ValueAEffectiveFlagAux and ValueAEffectiveFlagAuxInv.
    }
}
