// This file contains range-checking values for 0..=15.

use nexus_vm::riscv::{BuiltinOpcode, InstructionType};
use stwo_prover::constraint_framework::{logup::LogupTraceGenerator, Relation, RelationEntry};

use num_traits::{One, Zero};
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES},
    fields::m31::BaseField,
};

use crate::{
    column::{
        Column::{
            self, Multiplicity16, OpA1_4, OpB0_3, OpB1_4, OpC0_3, OpC12_15, OpC16_19, OpC1_4,
            OpC4_7,
        },
        PreprocessedColumn::{self, Range16},
    },
    components::AllLookupElements,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{
        IsAluImmShift, IsTypeB, IsTypeINoShift, IsTypeJ, IsTypeR, IsTypeS, IsTypeU, VirtualColumn,
    },
};

/// A Chip for range-checking values for 0..=15
///
/// Range16Chip needs to be located at the end of the chip composition together with the other range check chips
pub struct Range16Chip;

const LOOKUP_TUPLE_SIZE: usize = 1;
stwo_prover::relation!(Range16LookupElements, LOOKUP_TUPLE_SIZE);

const TYPE_R_CHECKED: [Column; 3] = [OpC0_3, OpA1_4, OpB1_4];
const TYPE_U_CHECKED: [Column; 2] = [OpC12_15, OpA1_4];
const TYPE_I_NO_SHIFT_CHECKED: [Column; 4] = [OpC0_3, OpC4_7, OpA1_4, OpB1_4];
const TYPE_I_SHIFT_CHECKED: [Column; 3] = [OpC0_3, OpA1_4, OpB1_4];
const TYPE_J_CHECKED: [Column; 4] = [OpC4_7, OpC12_15, OpC16_19, OpA1_4];
const TYPE_B_CHECKED: [Column; 3] = [OpC1_4, OpA1_4, OpB0_3];
const TYPE_S_CHECKED: [Column; 3] = [OpC1_4, OpA1_4, OpB0_3];

impl MachineChip for Range16Chip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        all_elements.insert(Range16LookupElements::draw(channel));
    }

    /// Increments Multiplicity16 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        fill_main_for_type::<IsTypeR>(
            traces,
            row_idx,
            step,
            InstructionType::RType,
            &TYPE_R_CHECKED,
        );
        fill_main_for_type::<IsTypeU>(
            traces,
            row_idx,
            step,
            InstructionType::UType,
            &TYPE_U_CHECKED,
        );
        fill_main_for_type::<IsTypeINoShift>(
            traces,
            row_idx,
            step,
            InstructionType::IType,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        fill_main_for_type::<IsAluImmShift>(
            traces,
            row_idx,
            step,
            InstructionType::ITypeShamt,
            &TYPE_I_SHIFT_CHECKED,
        );
        fill_main_for_type::<IsTypeJ>(
            traces,
            row_idx,
            step,
            InstructionType::JType,
            &TYPE_J_CHECKED,
        );
        fill_main_for_type::<IsTypeB>(
            traces,
            row_idx,
            step,
            InstructionType::BType,
            &TYPE_B_CHECKED,
        );
        fill_main_for_type::<IsTypeS>(
            traces,
            row_idx,
            step,
            InstructionType::SType,
            &TYPE_S_CHECKED,
        );
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &Range16LookupElements = lookup_element.as_ref();
        // Add checked occurrences to logup sum.
        fill_interaction_for_type::<IsTypeR>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_R_CHECKED,
        );
        fill_interaction_for_type::<IsTypeU>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_U_CHECKED,
        );
        fill_interaction_for_type::<IsTypeINoShift>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        fill_interaction_for_type::<IsAluImmShift>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_I_SHIFT_CHECKED,
        );
        fill_interaction_for_type::<IsTypeJ>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_J_CHECKED,
        );
        fill_interaction_for_type::<IsTypeB>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_B_CHECKED,
        );
        fill_interaction_for_type::<IsTypeS>(
            original_traces,
            lookup_element,
            logup_trace_gen,
            &TYPE_S_CHECKED,
        );
        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [&BaseColumn; Range16.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range16);
        let multiplicity_basecolumn: [&BaseColumn; Multiplicity16.size()] =
            original_traces.get_base_column(Multiplicity16);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let reference_tuple = vec![range_basecolumn[0].data[vec_row]];
            let denom = lookup_element.combine(&reference_tuple);
            let numerator = multiplicity_basecolumn[0].data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &AllLookupElements,
    ) {
        let lookup_elements: &Range16LookupElements = lookup_elements.as_ref();

        // Add checked occurrences to logup sum.
        add_constraints_for_type::<E, IsTypeR>(eval, trace_eval, lookup_elements, &TYPE_R_CHECKED);
        add_constraints_for_type::<E, IsTypeU>(eval, trace_eval, lookup_elements, &TYPE_U_CHECKED);
        add_constraints_for_type::<E, IsTypeINoShift>(
            eval,
            trace_eval,
            lookup_elements,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        add_constraints_for_type::<E, IsAluImmShift>(
            eval,
            trace_eval,
            lookup_elements,
            &TYPE_I_SHIFT_CHECKED,
        );
        add_constraints_for_type::<E, IsTypeJ>(eval, trace_eval, lookup_elements, &TYPE_J_CHECKED);
        add_constraints_for_type::<E, IsTypeB>(eval, trace_eval, lookup_elements, &TYPE_B_CHECKED);
        add_constraints_for_type::<E, IsTypeS>(eval, trace_eval, lookup_elements, &TYPE_S_CHECKED);

        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range16);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity16);
        let numerator: E::EF = (-multiplicity.clone()).into();

        eval.add_to_relation(RelationEntry::new(lookup_elements, numerator, &[range]));
    }
}

fn add_constraints_for_type<
    E: stwo_prover::constraint_framework::EvalAtRow,
    VR: VirtualColumn<1>,
>(
    eval: &mut E,
    trace_eval: &TraceEval<E>,
    lookup_elements: &Range16LookupElements,
    cols: &[Column],
) {
    let [numerator] = VR::eval(trace_eval);
    for col in cols.iter() {
        // not using trace_eval! macro because it doesn't accept *col as an argument.
        let [value] = trace_eval.column_eval(*col);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.clone().into(),
            &[value],
        ));
    }
}

fn fill_interaction_for_type<VC: VirtualColumn<1>>(
    original_traces: &FinalizedTraces,
    lookup_element: &Range16LookupElements,
    logup_trace_gen: &mut LogupTraceGenerator,
    cols: &[Column],
) {
    for col in cols.iter() {
        let [value_basecolumn]: [&BaseColumn; 1] = original_traces.get_base_column(*col);
        let log_size = original_traces.log_size();
        let logup_trace_gen: &mut LogupTraceGenerator = logup_trace_gen;
        // TODO: we can deal with two limbs at a time.
        let mut logup_col_gen = logup_trace_gen.new_col();
        // vec_row is row_idx divided by 16. Because SIMD.
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let checked_tuple = vec![value_basecolumn.data[vec_row]];
            let denom = lookup_element.combine(&checked_tuple);
            let [is_type] = VC::read_from_finalized_traces(original_traces, vec_row);
            logup_col_gen.write_frac(vec_row, is_type.into(), denom);
        }
        logup_col_gen.finalize_col();
    }
}

fn fill_main_for_type<VC: VirtualColumn<1>>(
    traces: &mut TracesBuilder,
    row_idx: usize,
    step: &Option<ProgramStep>,
    instruction_type: InstructionType,
    columns: &[Column],
) {
    let step_is_of_type = step
        .as_ref()
        .is_some_and(|step| step.step.instruction.ins_type == instruction_type);

    // For some reasons ECALL and EBREAK are considered to be IType, but they don't contain immediate values to range-check.
    if step.as_ref().is_some_and(|step| {
        matches!(
            step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK)
        )
    }) {
        return;
    }

    debug_assert_eq!(
        step_is_of_type,
        {
            let [is_type] = VC::read_from_traces_builder(traces, row_idx);
            !is_type.is_zero()
        },
        "ProgramStep and the TraceBuilder seem to disagree which type of instruction is being processed at row {}; step: {:?}, instruction_type: {:?}",
        row_idx,
        step,
        instruction_type,
    );
    if step_is_of_type {
        for col in columns.iter() {
            let [val] = traces.column(row_idx, *col);
            fill_main_elm(val, traces);
        }
    }
}

fn fill_main_elm(col: BaseField, traces: &mut TracesBuilder) {
    let checked = col.0;
    #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
    assert!(checked < 16, "value is out of range {}", checked);
    let multiplicity_col: [&mut BaseField; 1] = traces.column_mut(checked as usize, Multiplicity16);
    *multiplicity_col[0] += BaseField::one();
    // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    assert_ne!(*multiplicity_col[0], BaseField::zero());
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};

    use crate::trace::program_trace::ProgramTracesBuilder;
    use crate::traits::MachineChip;

    use nexus_vm::emulator::{Emulator, HarvardEmulator};

    use stwo_prover::core::fields::qm31::SecureField;

    #[test]
    fn test_range16_chip_success() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());

        let mut program_step = ProgramStep::default();
        let mut i = 0;

        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8;

            for col in TYPE_R_CHECKED
                .into_iter()
                .chain(TYPE_I_NO_SHIFT_CHECKED)
                .chain(TYPE_I_SHIFT_CHECKED)
                .chain(TYPE_J_CHECKED)
                .chain(TYPE_B_CHECKED)
                .chain(TYPE_S_CHECKED)
            {
                traces.fill_columns(row_idx, b, col);
            }

            match i {
                0 => {
                    traces.fill_columns(row_idx, true, Column::IsAdd);
                    program_step.step.instruction.ins_type = InstructionType::IType;
                    traces.fill_columns(row_idx, true, Column::ImmC);
                }
                1 => {
                    traces.fill_columns(row_idx, true, Column::IsAdd);
                    program_step.step.instruction.ins_type = InstructionType::RType;
                }
                2 => {
                    traces.fill_columns(row_idx, true, Column::IsSll);
                    program_step.step.instruction.ins_type = InstructionType::ITypeShamt;
                    traces.fill_columns(row_idx, true, Column::ImmC);
                }
                3 => {
                    traces.fill_columns(row_idx, true, Column::IsJal);
                    program_step.step.instruction.ins_type = InstructionType::JType;
                }
                4 => {
                    traces.fill_columns(row_idx, true, Column::IsBne);
                    program_step.step.instruction.ins_type = InstructionType::BType;
                }
                5 => {
                    traces.fill_columns(row_idx, true, Column::IsSb);
                    program_step.step.instruction.ins_type = InstructionType::SType;
                }
                _ => panic!("i must be in 0..6 range"),
            }
            i = (i + 1) % 6;

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &mut side_note,
            );
        }
        assert_chip::<Range16Chip>(traces, None);
    }

    #[test]
    fn test_range16_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default().finalize());
        let mut program_step = ProgramStep::default();
        program_step.step.instruction.ins_type = InstructionType::RType;

        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8 + 1; // sometimes out of range
            traces.fill_columns(row_idx, b, Column::OpB1_4);
            traces.fill_columns(row_idx, true, Column::IsAdd);

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &mut side_note,
            );
        }
        let CommittedTraces { claimed_sum, .. } =
            commit_traces::<Range16Chip>(config, &twiddles, &traces.finalize(), None);

        assert_ne!(claimed_sum, SecureField::zero());
    }
}
