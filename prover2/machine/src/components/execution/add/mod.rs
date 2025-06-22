use num_traits::One;
use stwo_prover::{
    constraint_framework::{EvalAtRow, RelationEntry},
    core::{
        backend::simd::{
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField, FieldExpOps},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
    original_base_column,
    program::{ProgramStep, Word},
    trace_eval,
};

use crate::{
    components::utils::{add_16bit_with_carry, add_with_carries, u32_to_16bit_parts_le},
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, ComponentLookupElements, CpuToInstLookupElements,
        InstToRegisterMemoryLookupElements, LogupTraceBuilder, ProgramExecutionLookupElements,
    },
    side_note::SideNote,
};

mod columns;
use columns::{Column, PreprocessedColumn};

pub const ADD: Add = Add::new(BuiltinOpcode::ADD);
pub const ADDI: Add = Add::new(BuiltinOpcode::ADDI);

pub struct Add {
    opcode: BuiltinOpcode,
    reg2_accessed: bool,
}

struct ExecutionResult {
    carry_bits: [bool; 2], // carry bits for 16-bit boundaries
    sum_bytes: Word,
}

impl Add {
    const REG1_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const REG3_ACCESSED: BaseField = BaseField::from_u32_unchecked(1);
    const REG3_WRITE: BaseField = BaseField::from_u32_unchecked(1);

    const fn new(opcode: BuiltinOpcode) -> Self {
        assert!(matches!(opcode, BuiltinOpcode::ADD | BuiltinOpcode::ADDI));
        Self {
            opcode,
            reg2_accessed: matches!(opcode, BuiltinOpcode::ADD),
        }
    }

    const fn opcode(&self) -> BaseField {
        BaseField::from_u32_unchecked(self.opcode.raw() as u32)
    }

    fn iter_program_steps<'a>(
        &self,
        side_note: &SideNote<'a>,
    ) -> impl Iterator<Item = ProgramStep<'a>> {
        let add_opcode = self.opcode;
        side_note.iter_program_steps().filter(move |step| {
            matches!(
                step.step.instruction.opcode.builtin(),
                opcode if opcode == Some(add_opcode),
            )
        })
    }

    fn execute_step(value_b: Word, value_c: Word) -> ExecutionResult {
        // Recompute 32-bit result from 8-bit limbs.
        let (sum_bytes, carry_bits) = add_with_carries(value_b, value_c);
        let carry_bits = [carry_bits[1], carry_bits[3]];

        ExecutionResult {
            carry_bits,
            sum_bytes,
        }
    }

    fn generate_trace_row(
        &self,
        trace: &mut TraceBuilder<Column>,
        row_idx: usize,
        vm_step: ProgramStep,
        _side_note: &mut SideNote,
    ) {
        let step = &vm_step.step;
        assert_eq!(step.instruction.opcode.builtin(), Some(self.opcode));

        let pc = step.pc;
        let pc_parts = u32_to_16bit_parts_le(pc);
        let (pc_next, pc_carry) = add_16bit_with_carry(pc_parts, WORD_SIZE as u16);

        let clk = step.timestamp;
        let clk_parts = u32_to_16bit_parts_le(clk);
        let (clk_next, clk_carry) = add_16bit_with_carry(clk_parts, 1u16);

        let value_b = vm_step.get_value_b();
        let (value_c, _) = vm_step.get_value_c();
        let ExecutionResult {
            carry_bits,
            sum_bytes,
        } = Self::execute_step(value_b, value_c);

        trace.fill_columns(row_idx, pc_parts, Column::Pc);
        trace.fill_columns(row_idx, pc_next, Column::PcNext);
        trace.fill_columns(row_idx, pc_carry, Column::PcCarry);

        trace.fill_columns(row_idx, clk_parts, Column::Clk);
        trace.fill_columns(row_idx, clk_next, Column::ClkNext);
        trace.fill_columns(row_idx, clk_carry, Column::ClkCarry);

        trace.fill_columns_bytes(row_idx, &value_b, Column::BVal);
        trace.fill_columns_bytes(row_idx, &value_c, Column::CVal);
        trace.fill_columns_bytes(row_idx, &sum_bytes, Column::AVal);
        trace.fill_columns(row_idx, carry_bits, Column::HCarry);
    }
}

impl BuiltInComponent for Add {
    type PreprocessedColumn = PreprocessedColumn;

    type MainColumn = Column;

    type LookupElements = (
        CpuToInstLookupElements,
        ProgramExecutionLookupElements,
        InstToRegisterMemoryLookupElements,
    );

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_add_steps = self.iter_program_steps(side_note).count();
        let log_size = num_add_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

        let mut trace = TraceBuilder::new(log_size);
        for (row_idx, program_step) in self.iter_program_steps(side_note).enumerate() {
            self.generate_trace_row(&mut trace, row_idx, program_step, side_note);
        }

        // fill padding
        for row_idx in num_add_steps..1 << log_size {
            trace.fill_columns(row_idx, true, Column::IsLocalPad);
        }
        trace.finalize()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (rel_cpu_to_inst, rel_cont_prog_exec, rel_inst_to_reg_memory) =
            Self::LookupElements::get(lookup_elements);
        let mut logup_trace_builder = LogupTraceBuilder::new(component_trace.log_size());

        let [is_local_pad] = original_base_column!(component_trace, Column::IsLocalPad);
        let clk = original_base_column!(component_trace, Column::Clk);
        let pc = original_base_column!(component_trace, Column::Pc);
        let a_val = original_base_column!(component_trace, Column::AVal);
        let b_val = original_base_column!(component_trace, Column::BVal);
        let c_val = original_base_column!(component_trace, Column::CVal);

        let clk_next = original_base_column!(component_trace, Column::ClkNext);
        let pc_next = original_base_column!(component_trace, Column::PcNext);

        // consume(rel-cpu-to-inst, 1−is-local-pad, (clk, opcode, pc, a-val, b-val, c-val))
        logup_trace_builder.add_to_relation_with(
            &rel_cpu_to_inst,
            [is_local_pad.clone()],
            |[is_local_pad]| (is_local_pad - PackedBaseField::one()).into(),
            &[
                &clk,
                std::slice::from_ref(&self.opcode().into()),
                &pc,
                &a_val,
                &b_val,
                &c_val,
            ]
            .concat(),
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
        //     (clk, a-val, b-val, c-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        let reg2_accessed = BaseField::from(self.reg2_accessed as u32);
        logup_trace_builder.add_to_relation_with(
            &rel_inst_to_reg_memory,
            [is_local_pad],
            |[is_local_pad]| (PackedBaseField::one() - is_local_pad).into(),
            &[
                clk.as_slice(),
                &a_val,
                &b_val,
                &c_val,
                &[
                    Add::REG1_ACCESSED.into(),
                    reg2_accessed.into(),
                    Add::REG3_ACCESSED.into(),
                    Add::REG3_WRITE.into(),
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
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let [clk_carry] = trace_eval!(trace_eval, Column::ClkCarry);
        let [pc_carry] = trace_eval!(trace_eval, Column::PcCarry);
        let [h_carry_1, h_carry_2] = trace_eval!(trace_eval, Column::HCarry);

        let pc = trace_eval!(trace_eval, Column::Pc);
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let clk = trace_eval!(trace_eval, Column::Clk);
        let clk_next = trace_eval!(trace_eval, Column::ClkNext);

        let a_val = trace_eval!(trace_eval, Column::AVal);
        let b_val = trace_eval!(trace_eval, Column::BVal);
        let c_val = trace_eval!(trace_eval, Column::CVal);

        // TODO: annotate
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[0].clone() + clk_carry.clone() * BaseField::from(1 << 16)
                    - clk[0].clone()
                    - E::F::one()),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (clk_next[1].clone() - clk[1].clone() - clk_carry.clone()),
        );

        // (clk-carry) · (1 − clk-carry) = 0
        eval.add_constraint(clk_carry.clone() * (E::F::one() - clk_carry.clone()));

        // TODO: annotate
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[0].clone() + pc_carry.clone() * BaseField::from(1 << 16)
                    - pc[0].clone()
                    - E::F::from(4.into())),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (pc_next[1].clone() - pc[1].clone() - pc_carry.clone()),
        );
        // (pc-carry) · (1 − pc-carry) = 0
        eval.add_constraint(pc_carry.clone() * (E::F::one() - pc_carry.clone()));

        let modulus = E::F::from(256u32.into());

        // TODO: annotate
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[0].clone()
                    + a_val[1].clone() * modulus.clone()
                    + h_carry_1.clone() * modulus.clone().pow(2)
                    - (b_val[0].clone()
                        + b_val[1].clone() * modulus.clone()
                        + c_val[0].clone()
                        + c_val[1].clone() * modulus.clone())),
        );
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (a_val[2].clone()
                    + a_val[3].clone() * modulus.clone()
                    + h_carry_2.clone() * modulus.clone().pow(2)
                    - (b_val[2].clone()
                        + b_val[3].clone() * modulus.clone()
                        + c_val[2].clone()
                        + c_val[3].clone() * modulus.clone()
                        + h_carry_1.clone())),
        );

        // Logup Interactions
        let (rel_cpu_to_inst, rel_cont_prog_exec, rel_inst_to_reg_memory) = lookup_elements;

        // consume(rel-cpu-to-inst, 1−is-local-pad, (clk, opcode, pc, a-val, b-val, c-val))
        eval.add_to_relation(RelationEntry::new(
            rel_cpu_to_inst,
            (is_local_pad.clone() - E::F::one()).into(),
            &[
                &clk,
                std::slice::from_ref(&E::F::from(self.opcode())),
                &pc,
                &a_val,
                &b_val,
                &c_val,
            ]
            .concat(),
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
        //     (clk, a-val, b-val, c-val, reg1-accessed, reg2-accessed, reg3-accessed, reg3-write)
        // )
        let reg2_accessed = E::F::from(BaseField::from(self.reg2_accessed as u32));
        eval.add_to_relation(RelationEntry::new(
            rel_inst_to_reg_memory,
            (E::F::one() - is_local_pad.clone()).into(),
            &[
                clk.as_slice(),
                &a_val,
                &b_val,
                &c_val,
                &[
                    Add::REG1_ACCESSED.into(),
                    reg2_accessed,
                    Add::REG3_ACCESSED.into(),
                    Add::REG3_WRITE.into(),
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
    fn assert_add_constraints() {
        let basic_block = vec![BasicBlock::new(vec![
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 3, 2, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 4, 3, 2),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 5, 4, 3),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 6, 5, 4),
        ])];
        let (view, program_trace) =
            k_trace_direct(&basic_block, 1).expect("error generating trace");

        let assert_ctx = &mut AssertContext::new(&program_trace, &view);
        let mut claimed_sum = SecureField::zero();

        claimed_sum += assert_component(ADD, assert_ctx);
        claimed_sum += assert_component(ADDI, assert_ctx);

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
