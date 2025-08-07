use std::marker::PhantomData;

use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_air_column::AirColumn;
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::{ProgramStep, Word},
    trace_eval,
    utils::zero_array,
};

use crate::{
    components::{
        execution::{
            common::{ExecutionComponent, ExecutionLookupEval},
            decoding::InstructionDecoding,
        },
        utils::{
            add_16bit_with_carry,
            constraints::{ClkIncrement, PcIncrement},
            subtract_with_borrow, u32_to_16bit_parts_le,
        },
    },
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, InstToProgMemoryLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
        RangeCheckLookupElements,
    },
    side_note::{program::ProgramTraceRef, range_check::RangeCheckAccumulator, SideNote},
};

mod columns;
mod sltiu;
mod sltu;

use columns::{Column, PreprocessedColumn};

pub const SLTU: Sltu<sltu::Sltu> = Sltu::new();
pub const SLTIU: Sltu<sltiu::Sltiu> = Sltu::new();

pub trait SltuOp:
    InstructionDecoding<PreprocessedColumn = PreprocessedColumn, MainColumn = Column>
{
}

pub struct Sltu<T> {
    _phantom: PhantomData<T>,
}

impl<T: SltuOp> ExecutionComponent for Sltu<T> {
    const OPCODE: BuiltinOpcode = <T as InstructionDecoding>::OPCODE;

    const REG1_ACCESSED: bool = true;
    const REG2_ACCESSED: bool = <T as InstructionDecoding>::REG2_ACCESSED;
    const REG3_ACCESSED: bool = true;
    const REG3_WRITE: bool = true;
}

struct ExecutionResult {
    borrow_bits: [bool; 2], // for 16-bit boundaries
    diff_bytes: Word,
}

impl<T: SltuOp> Sltu<T> {
    const fn new() -> Self {
        assert!(matches!(
            T::OPCODE,
            BuiltinOpcode::SLTU | BuiltinOpcode::SLTIU
        ));
        Self {
            _phantom: PhantomData,
        }
    }

    fn execute_step(value_b: Word, value_c: Word) -> ExecutionResult {
        let (diff_bytes, borrow_bits) = subtract_with_borrow(value_b, value_c);
        let borrow_bits = [borrow_bits[1], borrow_bits[3]];

        ExecutionResult {
            borrow_bits,
            diff_bytes,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        program_step: ProgramStep,
        range_check_accum: &mut RangeCheckAccumulator,
    ) {
        let step = &program_step.step;

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (_pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (_clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = program_step.get_value_b();
        let (value_c, _) = program_step.get_value_c();
        let ExecutionResult {
            borrow_bits,
            diff_bytes,
        } = Self::execute_step(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);

        trace.fill_columns(row_idx, borrow_bits, Column::HBorrow);
        trace.fill_columns(row_idx, diff_bytes, Column::HRem);

        range_check_accum.range256.add_values(&diff_bytes);
    }
}

impl<T: SltuOp> BuiltInComponent for Sltu<T> {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        InstToProgMemoryLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
        RangeCheckLookupElements,
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
        let mut local_trace = TraceBuilder::new(log_size);
        let mut range_check_accum = RangeCheckAccumulator::default();

        for (row_idx, program_step) in
            <Self as ExecutionComponent>::iter_program_steps(side_note).enumerate()
        {
            self.generate_trace_row(
                &mut common_trace,
                row_idx,
                program_step,
                &mut range_check_accum,
            );
            T::generate_trace_row(
                row_idx,
                &mut local_trace,
                program_step,
                &mut range_check_accum,
            );
        }
        side_note.range_check.append(range_check_accum);
        // fill padding
        for row_idx in num_steps..1 << log_size {
            common_trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }

        common_trace.finalize().concat(local_trace.finalize())
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
            Column::COLUMNS_NUM + T::DecodingColumn::COLUMNS_NUM
        );
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        // range check h-rem
        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let h_rem = original_base_column!(component_trace, Column::HRem);
        range_check.range256.generate_logup_col(
            &mut logup_trace_builder,
            is_local_pad.clone(),
            &h_rem,
        );

        <T as InstructionDecoding>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            &range_check,
        );
        <Self as ExecutionComponent>::generate_interaction_trace(
            &mut logup_trace_builder,
            &component_trace,
            side_note,
            &(
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            is_local_pad,
        );

        logup_trace_builder.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<Self::PreprocessedColumn, Self::MainColumn, E>,
        lookup_elements: &Self::LookupElements,
    ) {
        let (rel_inst_to_prog_memory, rel_cont_prog_exec, rel_inst_to_reg_memory, range_check) =
            lookup_elements;
        let local_trace_eval = TraceEval::new(eval);

        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let [h_borrow_1, h_borrow_2] = trace_eval!(trace_eval, Column::HBorrow);

        let h_rem = trace_eval!(trace_eval, Column::HRem);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = T::combine_c_val(&local_trace_eval);

        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = ClkIncrement {
            clk: Column::Clk,
            clk_carry: Column::ClkCarry,
        }
        .eval(eval, &trace_eval);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = PcIncrement {
            pc: Column::Pc,
            pc_carry: Column::PcCarry,
        }
        .eval(eval, &trace_eval);

        let modulus = E::F::from(256u32.into());

        // subtracting 2 limbs at a time
        //
        // (1 − is-local-pad) · (
        //     a-val(1) + a-val(2) · 2^8
        //     − h-borrow(1) · 2^16
        //     − (b-val(1) + b-val(2) · 2^8 − c-val(1) − c-val(2) · 2^8)
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem[0].clone() + h_rem[1].clone() * modulus.clone()
                    - h_borrow_1.clone() * modulus.clone().pow(2)
                    - (b_val[0].clone() + b_val[1].clone() * modulus.clone()
                        - c_val[0].clone()
                        - c_val[1].clone() * modulus.clone())),
        );
        // (1 − is-local-pad) · (
        //     a-val(3) + a-val(4) · 2^8
        //     − h-borrow(2) · 2^16
        //     − (b-val(3) + b-val(4) · 2^8 − c-val(3) − c-val(4) · 2^8 − h-borrow(1))
        // ) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_rem[2].clone() + h_rem[3].clone() * modulus.clone()
                    - h_borrow_2.clone() * modulus.clone().pow(2)
                    - (b_val[2].clone() + b_val[3].clone() * modulus.clone()
                        - c_val[2].clone()
                        - c_val[3].clone() * modulus.clone()
                        - h_borrow_1.clone())),
        );

        // range check h-rem
        range_check
            .range256
            .constrain(eval, is_local_pad.clone(), &h_rem);

        T::constrain_decoding(eval, &trace_eval, &local_trace_eval, range_check);

        // Logup Interactions
        let instr_val = T::combine_instr_val(&local_trace_eval);
        let reg_addrs = T::combine_reg_addresses(&local_trace_eval);

        let mut a_val = std::array::from_fn(|_i| E::F::zero());
        a_val[0] = h_borrow_2;

        let c_val = if Self::REG2_ACCESSED {
            c_val
        } else {
            zero_array::<WORD_SIZE, E>()
        };

        <Self as ExecutionComponent>::constrain_logups(
            eval,
            (
                rel_inst_to_prog_memory,
                rel_cont_prog_exec,
                rel_inst_to_reg_memory,
            ),
            ExecutionLookupEval {
                is_local_pad,
                reg_addrs,
                reg_values: [a_val, b_val, c_val],
                instr_val,
                clk,
                clk_next,
                pc,
                pc_next,
            },
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
    fn assert_sltu_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            // x2 = 1 because 0 < 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 0, 1),
            // x2 = 0 because 1 < 1 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 1),
            // x2 = 0 because 1 < 0 doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTU), 2, 1, 0),
            // SLTIU tests
            //
            // x3 = 1 because 0 < 1 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 1),
            // x3 = 0 because 1 < 1 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 1),
            // x3 = 1 because 1 < 2 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 2),
            // x3 = 0 because 2 < 1 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 2, 1),
            // x3 = 1 because any number < 0xFFF (4095 in decimal, treated as unsigned)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 1, 0xFFF),
            // x3 = 0 because 0 < 0 doesn't hold (testing with immediate 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 0, 0),
            // Set x4 = 10 for further testing
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 4, 0, 10),
            // x3 = 1 because 10 < 15 (immediate)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 15),
            // x3 = 0 because 10 < 5 (immediate) doesn't hold
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLTIU), 3, 4, 5),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(SLTU, assert_ctx);
        claimed_sum += assert_component(SLTIU, assert_ctx);

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
