use num_traits::One;
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    program::{ProgramStep, Word},
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::ExecutionComponent,
            decoding::{
                type_u::{self, TypeUDecoding},
                InstructionDecoding,
            },
        },
        utils::{
            add_16bit_with_carry, add_with_carries,
            constraints::{ClkIncrement, PcIncrement},
            u32_to_16bit_parts_le,
        },
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

pub const AUIPC: Auipc = Auipc;

pub struct Auipc;

impl ExecutionComponent for Auipc {
    const OPCODE: BuiltinOpcode = BuiltinOpcode::AUIPC;

    const REG1_ACCESSED: bool = false;
    const REG2_ACCESSED: bool = false;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;

    type Column = Column;
}

struct AuipcDecoding;
impl TypeUDecoding for AuipcDecoding {
    const OPCODE: BuiltinOpcode = Auipc::OPCODE;
    const IS_LOCAL_PAD: Self::MainColumn = Column::IsLocalPad;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
}

type Decoding = type_u::TypeU<AuipcDecoding>;

struct ExecutionResult {
    pub value_a: Word,
    pub carry_bits: [bool; 2], // carry bits for 16-bit boundaries
}

impl Auipc {
    fn execute_step(program_step: &ProgramStep) -> ExecutionResult {
        let pc = program_step.step.pc.to_le_bytes();
        let imm = (program_step.step.instruction.op_c << 12).to_le_bytes();

        // value_a = pc + (imm << 12)
        let (value_a, carry_bits) = add_with_carries(pc, imm);
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            value_a,
            carry_bits,
        }
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
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        let ExecutionResult {
            value_a,
            carry_bits,
        } = Self::execute_step(&program_step);
        trace.fill_columns(row_idx, value_a, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
    }
}

impl BuiltInComponent for Auipc {
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
        let num_steps = <Self as ExecutionComponent>::iter_program_steps(side_note).count();
        let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut common_trace = TraceBuilder::new(log_size);
        let mut decoding_trace = TraceBuilder::new(log_size);

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(&mut common_trace, row_idx, program_step);
            type_u::generate_trace_row(row_idx, &mut decoding_trace, program_step);
        }
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(decoding_trace.finalize())
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
        assert_eq!(
            component_trace.original_trace.len(),
            Column::COLUMNS_NUM + type_u::DecodingColumn::COLUMNS_NUM
        );
        let lookup_elements = Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        <Self as ExecutionComponent>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            side_note,
            &lookup_elements,
        );
        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        ClkIncrement {
            is_local_pad: Column::IsLocalPad,
            clk: Column::Clk,
            clk_next: Column::ClkNext,
            clk_carry: Column::ClkCarry,
        }
        .constrain(eval, &trace_eval);
        PcIncrement {
            is_local_pad: Column::IsLocalPad,
            pc: Column::Pc,
            pc_next: Column::PcNext,
            pc_carry: Column::PcCarry,
        }
        .constrain(eval, &trace_eval);

        let decoding_trace_eval =
            TraceEval::<EmptyPreprocessedColumn, type_u::DecodingColumn, E>::new(eval);
        let c_val = type_u::CVal.eval(&decoding_trace_eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let a_val = trace_eval!(trace_eval, Column::AVal);
        let [pc_low, pc_high] = trace_eval!(trace_eval, Column::Pc);
        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);

        // add two bytes at a time
        //
        // (1 − is-local-pad) · (pc(1) + c-val(1) − a-val(1) − h-carry(1) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(2) + c-val(2) + h-carry(1) − a-val(2) − h-carry(2) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone()
                    + a_val[1].clone() * BaseField::from(1 << 8)
                    + h_carry_1.clone() * BaseField::from(1 << 8).pow(2)
                    - (pc_low + c_val[0].clone() + c_val[1].clone() * BaseField::from(1 << 8))),
        );
        // (1 − is-local-pad) · (pc(3) + c-val(3) + h-carry(2) − a-val(3) − h-carry(3) · 2^8 ) = 0
        // (1 − is-local-pad) · (pc(4) + c-val(4) + h-carry(3) − a-val(4) − h-carry(4) · 2^8 ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone()
                    + a_val[3].clone() * BaseField::from(1 << 8)
                    + h_carry_2.clone() * BaseField::from(1 << 8).pow(2)
                    - (pc_high
                        + c_val[2].clone()
                        + c_val[3].clone() * BaseField::from(1 << 8)
                        + h_carry_1.clone())),
        );
        // (h-carry(1)) · (1 − h-carry(1) ) = 0
        // (h-carry(2)) · (1 − h-carry(2) ) = 0
        eval.add_constraint(h_carry_1.clone() * (E::F::one() - h_carry_1));
        eval.add_constraint(h_carry_2.clone() * (E::F::one() - h_carry_2));

        Decoding::constrain_decoding(eval, &trace_eval, &decoding_trace_eval);

        // Logup Interactions
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;
        let reg_addrs = Decoding::combine_reg_addresses(&decoding_trace_eval);
        let instr_val = Decoding::combine_instr_val(&decoding_trace_eval);

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            &trace_eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            reg_addrs,
            [
                a_val,
                zero_array::<WORD_SIZE, E>(),
                zero_array::<WORD_SIZE, E>(),
            ],
            instr_val,
        );

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        components::{
            Cpu, CpuBoundary, ProgramMemory, ProgramMemoryBoundary, RegisterMemory,
            RegisterMemoryBoundary,
        },
        framework::test_utils::{assert_component, components_claimed_sum, AssertContext},
    };
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };
    use num_traits::Zero;

    #[test]
    fn assert_auipc_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Case 1: AUIPC with a small positive value
            // AUIPC x1, 0x1 (x1 = PC + 0x1000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 1, 0, 0x1),
            // Case 2: AUIPC with a large positive value
            // AUIPC x2, 0xFFFFF (x2 = PC + 0xFFFFF000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 2, 0, 0xFFFFF),
            // Case 3: AUIPC with zero
            // AUIPC x3, 0x0 (x3 = PC + 0x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 3, 0, 0x0),
            // Case 4: AUIPC with a value that sets some interesting bit patterns
            // AUIPC x4, 0xABCDE (x4 = PC + 0xABCDE000)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 4, 0, 0xABCDE),
            // Case 5: AUIPC with x0 as destination (should not change x0)
            // AUIPC x0, 0x12345 (Should not change x0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::AUIPC), 0, 0, 0x12345),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(Auipc, assert_ctx);

        claimed_sum += components_claimed_sum(
            &[
                &Cpu,
                &CpuBoundary,
                &RegisterMemory,
                &RegisterMemoryBoundary,
                &ProgramMemory,
                &ProgramMemoryBoundary,
            ],
            assert_ctx,
        );

        assert!(claimed_sum.is_zero());
    }
}
