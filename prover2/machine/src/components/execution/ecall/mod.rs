//! ┌────────────┬───────────────────────────────────────────────────────────────┬────────────────┐
//! │ R[x17] val │ Description of `ecall` / `ebreak` functionality               │ PC update      │
//! ├────────────┼───────────────────────────────────────────────────────────────┼────────────────┤
//! │ 0x200      │ System call to write to memory (for debugging)                │ pc ← pc + 4    │
//! │ 0x201      │ System call to halt the virtual machine (similar to `unimp`)  │ pc not updated │
//! │ 0x400      │ System call to read from private input, loads 32-bit value    │ pc ← pc + 4    │
//! │            │ onto R[x10]                                                   │                │
//! │ 0x401      │ System call to obtain the current cycle count                 │ pc ← pc + 4    │
//! │ 0x402      │ System call to overwrite the stack pointer, loads value into  │ pc ← pc + 4    │
//! │            │ R[x2]                                                         │                │
//! │ 0x403      │ System call to overwrite the heap pointer, loads value into   │ pc ← pc + 4    │
//! │            │ R[x10]                                                        │                │
//! │ 0x405      │ System call for heap allocation                               │ pc ← pc + 4    │
//! └────────────┴───────────────────────────────────────────────────────────────┴────────────────┘

use nexus_common::constants::WORD_SIZE_HALVED;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, SyscallCode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    program::ProgramStep,
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::common::{ExecutionComponentColumn, ExecutionComponentTrace},
        utils::{add_16bit_with_carry, constraints::ClkIncrement, u32_to_16bit_parts_le},
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
    },
    side_note::{program::ProgramTraceRef, SideNote},
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub const ECALL: Ecall = Ecall;

pub struct Ecall;

impl Ecall {
    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = false;

    fn iter_program_steps<'a>(side_note: &'a SideNote) -> impl Iterator<Item = ProgramStep<'a>> {
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                Some(BuiltinOpcode::EBREAK) | Some(BuiltinOpcode::ECALL),
            )
        })
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);
        let b_val = program_step.get_value_b();

        trace.fill_columns(row_idx, pc_parts, Column::Pc);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns(row_idx, [b_val[0], b_val[1]], Column::BVal);

        let syscall_number = program_step
            .get_syscall_code()
            .expect("ECALL must have syscall number at Register::X17");

        let result = program_step.step.result;
        let mut a_val = [0u8; WORD_SIZE];

        let (syscall_flag, reg3_accessed) = match (syscall_number, result) {
            (0x200, None) => (Column::IsSysDebug, false),
            (0x201, result) => {
                // the result may be present or not depending on a pass, has no effect
                let _ = result;
                (Column::IsSysHalt, false)
            }
            (0x400, Some(result)) => {
                a_val = result.to_le_bytes();
                (Column::IsSysPrivInput, true)
            }
            (0x401, None) => (Column::IsSysCycleCount, false),
            (0x402, Some(result)) => {
                a_val = result.to_le_bytes();
                (Column::IsSysStackReset, true)
            }
            (0x403, Some(result)) => {
                a_val = result.to_le_bytes();
                (Column::IsSysHeapReset, true)
            }
            (0x405, None) => (Column::IsSysMemoryAdvise, false),
            _ => {
                panic!(
                    "Unknown syscall number: 0x{:x} and result: {:?}, on row {}",
                    syscall_number, result, row_idx
                );
            }
        };

        let (pc_next, pc_carry) = if syscall_number == 0x201 {
            (pc_parts, false)
        } else {
            add_16bit_with_carry(pc_parts, 4)
        };
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);

        trace.fill_columns(row_idx, reg3_accessed, Column::Reg3Accessed);
        trace.fill_columns(row_idx, a_val, Column::AVal);
        trace.fill_columns(row_idx, true, syscall_flag);
    }
}

impl BuiltInComponent for Ecall {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program: &ProgramTraceRef,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = Self::iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in Self::iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
        }
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        assert_eq!(component_trace.original_trace.len(), Column::COLUMNS_NUM);
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        // reg3-accessed is not a constant for ecall
        //
        // generate logups manually

        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);

        let decoding_trace = ExecutionComponentTrace::new(
            component_trace.log_size(),
            Self::iter_program_steps(side_note),
        );
        let instr_val =
            decoding_trace.base_column::<{ WORD_SIZE }>(ExecutionComponentColumn::InstrVal);

        let [op_a] = decoding_trace.base_column(ExecutionComponentColumn::OpA);
        let clk = decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::Clk);
        let clk_next =
            decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::ClkNext);
        let pc = decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::Pc);
        let pc_next =
            decoding_trace.base_column::<WORD_SIZE_HALVED>(ExecutionComponentColumn::PcNext);
        let a_val = decoding_trace.a_val();

        let zeroed_reg = [0u32; WORD_SIZE].map(|byte| BaseField::from(byte).into());
        let op_b = BaseField::from(17);
        let b_val = decoding_trace.b_val();
        let (op_c, c_val) = (BaseField::zero().into(), zeroed_reg);

        let [reg3_accessed] = component_trace.original_base_column(Column::Reg3Accessed);

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_prog_memory,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        );
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        logup_trace_builder.add_to_relation_with(
            &rel_cont_prog_exec,
            [is_local_pad.clone()],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[clk_next, pc_next].concat(),
        );
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b.into(), op_c],
                &a_val,
                &b_val,
                &c_val,
                &[
                    BaseField::from(Self::REG1_ACCESSED as u32).into(),
                    BaseField::from(Self::REG2_ACCESSED as u32).into(),
                    reg3_accessed.clone(),
                    reg3_accessed,
                ],
            ]
            .concat(),
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let [b_val_1, b_val_2] = trace_eval!(trace_eval, Column::BVal);
        let [reg3_accessed] = trace_eval!(trace_eval, Column::Reg3Accessed);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let [pc_carry] = trace_eval!(trace_eval, Column::PcCarry);

        let clk = trace_eval!(trace_eval, Column::Clk);

        let clk_next = ClkIncrement {
            clk: Column::Clk,
            clk_carry: Column::ClkCarry,
        }
        .eval(eval, &trace_eval);

        let [is_sys_debug] = trace_eval.column_eval(Column::IsSysDebug);
        let [is_sys_halt] = trace_eval.column_eval(Column::IsSysHalt);
        let [is_sys_priv_input] = trace_eval.column_eval(Column::IsSysPrivInput);
        let [is_sys_cycle_count] = trace_eval.column_eval(Column::IsSysCycleCount);
        let [is_sys_stack_reset] = trace_eval.column_eval(Column::IsSysStackReset);
        let [is_sys_heap_reset] = trace_eval.column_eval(Column::IsSysHeapReset);
        let [is_sys_mem_advise] = trace_eval.column_eval(Column::IsSysMemoryAdvise);

        // (is-sys-debug)(b-val(1) − 0x00) = 0
        // (is-sys-debug)(b-val(2) − 0x02) = 0
        //
        // (is-sys-halt)(b-val(1) − 0x01) = 0
        // (is-sys-halt)(b-val(2) − 0x02) = 0
        //
        // (is-sys-priv-input)(b-val(1) − 0x00) = 0
        // (is-sys-priv-input)(b-val(2) − 0x04) = 0
        //
        // (is-sys-cycle-count)(b-val(1) − 0x01) = 0
        // (is-sys-cycle-count)(b-val(2) − 0x04) = 0
        //
        // (is-sys-stack-reset)(b-val(1) − 0x02) = 0
        // (is-sys-stack-reset)(b-val(2) − 0x04) = 0
        //
        // (is-sys-heap-reset)(b-val(1) − 0x03) = 0
        // (is-sys-heap-reset)(b-val(2) − 0x04) = 0
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
            (SyscallCode::MemoryAdvise as u32, &is_sys_mem_advise),
        ];
        for (code, syscall_flag) in syscall_table {
            let code_bytes = code.to_le_bytes();
            assert!(code_bytes[2] == 0 && code_bytes[3] == 0);
            eval.add_constraint(
                syscall_flag.clone()
                    * (b_val_1.clone() - E::F::from(BaseField::from(code_bytes[0] as u32))),
            );
            eval.add_constraint(
                syscall_flag.clone()
                    * (b_val_2.clone() - E::F::from(BaseField::from(code_bytes[1] as u32))),
            );
            eval.add_constraint(syscall_flag.clone() * (E::F::one() - syscall_flag.clone()));
        }

        // (1 − is-local-pad) · (
        //     is_sys_debug
        //     + is_sys_halt
        //     + is_sys_priv_input
        //     + is_sys_cycle_count
        //     + is_sys_stack_reset
        //     + is_sys_heap_reset
        //     − 1
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (is_sys_debug.clone()
                    + is_sys_halt.clone()
                    + is_sys_priv_input.clone()
                    + is_sys_cycle_count.clone()
                    + is_sys_stack_reset.clone()
                    + is_sys_heap_reset.clone()
                    + is_sys_mem_advise.clone()
                    - E::F::one()),
        );

        // (1 − is-local-pad) · (is-sys-debug + is-sys-halt + is-sys-cycle-count) · (a-val(1) + a-val(2) · 2^8 ) = 0
        // (1 − is-local-pad) · (is-sys-debug + is-sys-halt + is-sys-cycle-count) · (a-val(3) + a-val(4) · 2^8 ) = 0
        eval.add_constraint(
            (is_sys_debug.clone() + is_sys_halt.clone() + is_sys_cycle_count.clone())
                * (a_val[0].clone() + a_val[1].clone() * BaseField::from(1 << 8)),
        );
        eval.add_constraint(
            (is_sys_debug.clone() + is_sys_halt.clone() + is_sys_cycle_count.clone())
                * (a_val[1].clone() + a_val[2].clone() * BaseField::from(1 << 8)),
        );

        // (1 − is-local-pad) · (is-sys-halt) · (pc(1) + pc(2) · 2^8 − pc-next(1) − pc-next(2) · 2^8) = 0
        // (1 − is-local-pad) · (is-sys-halt) · (pc(3) + pc(4) · 2^8 − pc-next(3) − pc-next(4) · 2^8) = 0
        eval.add_constraint(is_sys_halt.clone() * (pc[0].clone() - pc_next[0].clone()));
        eval.add_constraint(is_sys_halt.clone() * (pc[1].clone() - pc_next[1].clone()));

        let enforce_pc_increment = is_sys_debug.clone()
            + is_sys_priv_input.clone()
            + is_sys_cycle_count.clone()
            + is_sys_stack_reset.clone()
            + is_sys_heap_reset.clone()
            + is_sys_mem_advise.clone();
        // any other syscall increments the program counter
        //
        // enforce_pc_increment · (
        //     pc-next(1) + pc-carry(1) · 2^16
        //     − pc(1) − 4
        // ) = 0
        eval.add_constraint(
            enforce_pc_increment.clone()
                * (pc_next[0].clone() + pc_carry.clone() * BaseField::from(1 << 16)
                    - pc[0].clone()
                    - E::F::from(4.into())),
        );
        // enforce_pc_increment · (pc-next(2) − pc(2) − pc-carry(1)) = 0
        eval.add_constraint(
            enforce_pc_increment * (pc_next[1].clone() - pc[1].clone() - pc_carry.clone()),
        );

        // (1 − is-local-pad) · (is-sys-priv-input + is-sys-heap-reset + is-sys-stack-reset − reg3-accessed) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (is_sys_priv_input.clone()
                    + is_sys_heap_reset.clone()
                    + is_sys_stack_reset.clone()
                    - reg3_accessed.clone()),
        );
        // (reg3-accessed) · (1 − reg3-accessed) = 0
        eval.add_constraint(reg3_accessed.clone() * (E::F::one() - reg3_accessed.clone()));

        // Logup Interactions
        let op_a = (is_sys_priv_input.clone() + is_sys_heap_reset.clone()) * BaseField::from(10)
            + is_sys_stack_reset.clone() * BaseField::from(2);
        let op_b = E::F::from(BaseField::from(17));
        let op_c = E::F::zero();
        let mut instr_val = zero_array::<WORD_SIZE, E>();
        instr_val[0] = E::F::from(BaseField::from(0b01110011u32));

        // consume(rel-inst-to-prog-memory, 1−is-local-pad, (pc, instr-val))
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_prog_memory,
            (is_local_pad.clone() - E::F::one()).into(),
            &[pc.as_slice(), &instr_val].concat(),
        ));
        // provide(rel-cont-prog-exec, 1 − is-local-pad, (clk-next, pc-next))
        eval.add_to_relation(RelationEntry::new(
            rel_cont_prog_exec,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk_next[0].clone(),
                clk_next[1].clone(),
                pc_next[0].clone(),
                pc_next[1].clone(),
            ],
        ));
        // provide(
        //     rel-inst-to-reg-memory,
        //     1 − is-local-pad,
        //     (
        //         clk,
        //         op-a, op-b, op-c,
        //         a-val, b-val, c-val,
        //         reg1-accessed, reg2-accessed, reg3-accessed,
        //         reg3-write
        //     )
        // )
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &[op_a, op_b, op_c],
                &a_val,
                &[b_val_1, b_val_2, E::F::zero(), E::F::zero()],
                &zero_array::<WORD_SIZE, E>(),
                &[
                    BaseField::from(Self::REG1_ACCESSED as u32).into(),
                    BaseField::from(Self::REG2_ACCESSED as u32).into(),
                    reg3_accessed.clone(),
                    reg3_accessed,
                ],
            ]
            .concat(),
        ));
        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary, ADDI, RANGE16, RANGE256, RANGE64, RANGE8,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };

    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_syscall_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Debug syscall (0x200)
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADDI),
                17,
                0,
                SyscallCode::Write as u32,
            ),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Private input syscall (0x400)
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADDI),
                17,
                0,
                SyscallCode::ReadFromPrivateInput as u32,
            ),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Stack reset syscall (0x402)c
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADDI),
                17,
                0,
                SyscallCode::OverwriteStackPointer as u32,
            ),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // Heap reset syscall (0x403)
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADDI),
                17,
                0,
                SyscallCode::OverwriteHeapPointer as u32,
            ),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // End with Halt syscall (0x201)
            Instruction::new_ir(
                Opcode::from(BuiltinOpcode::ADDI),
                17,
                0,
                SyscallCode::Exit as u32,
            ),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            // If the PC reach here, if should panic because the program has already exited
            Instruction::unimpl(),
            Instruction::unimpl(),
            Instruction::unimpl(),
        ])];

        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(Ecall, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
                &ADDI,
                &RANGE8,
                &RANGE16,
                &RANGE64,
                &RANGE256,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
