use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_vm::{riscv::BuiltinOpcode, SyscallCode};

use crate::{
    column::Column::{self},
    components::AllLookupElements,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::IsTypeSys,
};

use crate::virtual_column::VirtualColumn;

pub struct SyscallChip;

impl MachineChip for SyscallChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return, // padding
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK)
        ) {
            return;
        }

        let syscall_number = vm_step
            .get_syscall_code()
            .expect("ECALL must have syscall number at Register::X17");

        let result = vm_step.step.result;
        match (syscall_number, result) {
            (0x200, None) => traces.fill_columns(row_idx, true, Column::IsSysDebug),
            (0x201, result) => {
                // the result may be present or not depending on a pass, has no effect
                let _ = result;

                traces.fill_columns(row_idx, true, Column::IsSysHalt);
                // PcNext should be the current Pc
                traces.fill_columns(row_idx, vm_step.step.pc, Column::PcNext);
            }
            (0x400, Some(result)) => {
                traces.fill_columns(row_idx, true, Column::IsSysPrivInput);
                traces.fill_columns(row_idx, result, Column::ValueA);
            }
            (0x401, None) => traces.fill_columns(row_idx, true, Column::IsSysCycleCount),
            (0x402, Some(result)) => {
                traces.fill_columns(row_idx, true, Column::IsSysStackReset);
                traces.fill_columns(row_idx, result, Column::ValueA);
            }
            (0x403, Some(result)) => {
                traces.fill_columns(row_idx, true, Column::IsSysHeapReset);
                traces.fill_columns(row_idx, result, Column::ValueA);
            }
            _ => {
                panic!(
                    "Unknown syscall number: 0x{:x} and result: {:?}, on row {}",
                    syscall_number, result, row_idx
                );
            }
        };
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let [is_type_sys] = IsTypeSys::eval(trace_eval);
        let [is_sys_debug] = trace_eval!(trace_eval, Column::IsSysDebug);
        let [is_sys_halt] = trace_eval!(trace_eval, Column::IsSysHalt);
        let [is_sys_priv_input] = trace_eval!(trace_eval, Column::IsSysPrivInput);
        let [is_sys_cycle_count] = trace_eval!(trace_eval, Column::IsSysCycleCount);
        let [is_sys_stack_reset] = trace_eval!(trace_eval, Column::IsSysStackReset);
        let [is_sys_heap_reset] = trace_eval!(trace_eval, Column::IsSysHeapReset);
        let value_b = trace_eval!(trace_eval, Column::ValueB);

        // is_type_sys・				(b_val_3) = 0
        // is_type_sys・				(b_val_4) = 0
        // is_type_sys・is_sys_debug・		(b_val_1 - 0x00) = 0  // b_val=0x200
        // is_type_sys・is_sys_debug・		(b_val_2 - 0x02) = 0  // b_val=0x200
        // is_type_sys・is_sys_halt・		(b_val_1 - 0x01) = 0  // b_val=0x201
        // is_type_sys・is_sys_halt・		(b_val_2 - 0x02) = 0  // b_val=0x201
        // is_type_sys・is_sys_priv_input・	(b_val_1 - 0x00) = 0  // b_val=0x400
        // is_type_sys・is_sys_priv_input・	(b_val_2 - 0x04) = 0  // b_val=0x400
        // is_type_sys・is_sys_cycle_count・	(b_val_1 - 0x01) = 0  // b_val=0x401
        // is_type_sys・is_sys_cycle_count・	(b_val_2 - 0x04) = 0  // b_val=0x401
        // is_type_sys・is_sys_stack_reset・	(b_val_1 - 0x02) = 0  // b_val=0x402
        // is_type_sys・is_sys_stack_reset・	(b_val_2 - 0x04) = 0  // b_val=0x402
        // is_type_sys・is_sys_heap_reset・	(b_val_1 - 0x03) = 0  // b_val=0x403
        // is_type_sys・is_sys_heap_reset・	(b_val_2 - 0x04) = 0  // b_val=0x403

        let syscall_table = [
            (SyscallCode::Write as u32, &is_sys_debug),
            (SyscallCode::Exit as u32, &is_sys_halt),
            (SyscallCode::ReadFromPrivateInput as u32, &is_sys_priv_input),
            (SyscallCode::CycleCount as u32, &is_sys_cycle_count),
            (
                SyscallCode::OverwriteStackPointer as u32,
                &is_sys_stack_reset,
            ),
            (SyscallCode::OverwriteHeapPointer as u32, &is_sys_heap_reset),
        ];

        eval.add_constraint(is_type_sys.clone() * value_b[2].clone());
        eval.add_constraint(is_type_sys.clone() * value_b[3].clone());

        for (code, is_sys) in syscall_table {
            let value_codes = u16::try_from(code)
                .expect("Syscall code must be in u16 range")
                .to_le_bytes();
            for (vc, vb) in value_codes.iter().zip(value_b.clone()) {
                eval.add_constraint(
                    is_type_sys.clone()
                        * is_sys.clone()
                        * (vb - E::F::from(BaseField::from(*vc as u32))),
                );
            }
        }

        // Enforce that one flag is set
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_priv_input + is_sys_cycle_count + is_sys_stack_reset + is_sys_heap_reset - 1) = 0
        eval.add_constraint(
            is_type_sys.clone()
                * (is_sys_debug.clone()
                    + is_sys_halt.clone()
                    + is_sys_priv_input.clone()
                    + is_sys_cycle_count.clone()
                    + is_sys_stack_reset.clone()
                    + is_sys_heap_reset.clone()
                    - E::F::one()),
        );

        // Enforcing values for op_a
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_cycle_count)・(op_a) = 0
        // is_type_sys・(is_sys_priv_input + is_sys_heap_reset)・(10 - op_a) = 0
        // is_type_sys・(is_sys_stack_reset)・(2 - op_a) = 0
        let [op_a] = trace_eval!(trace_eval, Column::OpA);

        eval.add_constraint(
            is_type_sys.clone()
                * (is_sys_debug.clone() + is_sys_halt.clone() + is_sys_cycle_count.clone())
                * op_a.clone(),
        );
        eval.add_constraint(
            is_type_sys.clone()
                * (is_sys_priv_input.clone() + is_sys_heap_reset.clone())
                * (E::F::from(BaseField::from(10)) - op_a.clone()),
        );
        eval.add_constraint(
            is_type_sys.clone()
                * is_sys_stack_reset.clone()
                * (E::F::from(BaseField::from(2)) - op_a.clone()),
        );

        // Enforcing ranges for a_val
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_cycle_count)・(a_val_1) = 0
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_cycle_count)・(a_val_2) = 0
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_cycle_count)・(a_val_3) = 0
        // is_type_sys・(is_sys_debug + is_sys_halt + is_sys_cycle_count)・(a_val_4) = 0
        let value_a = trace_eval!(trace_eval, Column::ValueA);
        for a in value_a {
            eval.add_constraint(
                is_type_sys.clone()
                    * (is_sys_debug.clone() + is_sys_halt.clone() + is_sys_cycle_count.clone())
                    * a,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip,
        },
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
        SyscallCode,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    #[rustfmt::skip]
    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Debug syscall (0x200)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, SyscallCode::Write as u32),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Private input syscall (0x400)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, SyscallCode::ReadFromPrivateInput as u32),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Stack reset syscall (0x402)c
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, SyscallCode::OverwriteStackPointer as u32),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Heap reset syscall (0x403)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, SyscallCode::OverwriteHeapPointer as u32),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // End with Halt syscall (0x201)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, SyscallCode::Exit as u32),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),

            // If the PC reach here, if should panic because the program has already exited
            Instruction::unimpl(),
            Instruction::unimpl(),
            Instruction::unimpl(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_syscall_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            SyscallChip,
            AddChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_traces = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_traces, &view);

        // We iterate each block in the trace for each instruction
        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, Some(program_traces.finalize()));
    }
}
