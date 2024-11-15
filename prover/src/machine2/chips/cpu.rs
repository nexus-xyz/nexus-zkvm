use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use crate::machine2::{
    column::Column::{self, *},
    trace::{eval::TraceEval, trace_column_mut, ProgramStep, Traces},
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
        let is_opcode = match step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI) => {
                trace_column_mut!(traces, row_idx, IsAdd)
            }
            Some(BuiltinOpcode::SUB) => {
                trace_column_mut!(traces, row_idx, IsSub)
            }
            _ => panic!(
                "Unsupported opcode: {:?}",
                step.instruction.opcode.builtin()
            ),
        };
        // Set is_opcode to 1, e.g If this is ADD opcode, set IsAdd to 1.
        *is_opcode[0] = BaseField::from(1);

        let pc_bytes = pc.to_le_bytes();
        let clk_bytes = clk.to_le_bytes();

        let pc_val = trace_column_mut!(traces, row_idx, Pc);
        for (i, b) in pc_bytes.iter().enumerate() {
            *pc_val[i] = BaseField::from(*b as u32);
        }
        let clk_val = trace_column_mut!(traces, row_idx, Clk);
        for (i, b) in clk_bytes.iter().enumerate() {
            *clk_val[i] = BaseField::from(*b as u32);
        }

        // Fill ValueB and ValueC to the main trace
        let value_b = vm_step.get_value_b();
        let (value_c, _) = vm_step.get_value_c();
        let value_b_col = trace_column_mut!(traces, row_idx, ValueB);
        for (i, b) in value_b.iter().enumerate() {
            *value_b_col[i] = BaseField::from(*b as u32);
        }
        let value_c_col = trace_column_mut!(traces, row_idx, ValueC);
        for (i, b) in value_c.iter().enumerate() {
            *value_c_col[i] = BaseField::from(*b as u32);
        }
    }

    fn add_constraints<E: EvalAtRow>(_eval: &mut E, _trace_eval: &TraceEval<E>) {
        // TODO: add constraints for the CPU chip.
    }
}
