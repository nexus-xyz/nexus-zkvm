// This file contains range-checking values for 0..=15.

use nexus_vm::riscv::InstructionType;
use stwo_prover::constraint_framework::logup::{LogupTraceGenerator, LookupElements};

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{logup::LogupAtRow, INTERACTION_TRACE_IDX},
    core::{
        backend::simd::{column::BaseColumn, m31::LOG_N_LANES, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField},
        lookups::utils::Fraction,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{
    column::{
        Column::{self, Multiplicity16, OpA14, OpB14, OpC03, OpC12_15, OpC47},
        PreprocessedColumn::{self, IsFirst, Range16},
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::{ProgramTraces, ProgramTracesBuilder},
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{IsAluImmShift, IsTypeINoShift, IsTypeR, IsTypeU, VirtualColumn},
};

/// A Chip for range-checking values for 0..=15
///
/// Range16Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range16Chip;

const TYPE_R_CHECKED: [Column; 3] = [OpC03, OpA14, OpB14];
const TYPE_U_CHECKED: [Column; 2] = [OpC12_15, OpA14];
const TYPE_I_NO_SHIFT_CHECKED: [Column; 4] = [OpC03, OpC47, OpA14, OpB14];
const TYPE_I_SHIFT_CHECKED: [Column; 3] = [OpC03, OpA14, OpB14];

impl MachineChip for Range16Chip {
    /// Increments Multiplicity16 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
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
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &LookupElements<12>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        // Add checked occurrences to logup sum.
        fill_interaction_for_type::<IsTypeR>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_R_CHECKED,
        );
        fill_interaction_for_type::<IsTypeU>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_U_CHECKED,
        );
        fill_interaction_for_type::<IsTypeINoShift>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        fill_interaction_for_type::<IsAluImmShift>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_I_SHIFT_CHECKED,
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

        let (ret, _total_logup_sum) = logup_trace_gen.finalize_last();
        #[cfg(not(test))] // Tests need to go past this assertion and break constraints.
        assert_eq!(_total_logup_sum, SecureField::zero());
        ret
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        let [is_first] = preprocessed_trace_eval!(trace_eval, IsFirst);
        let mut logup =
            LogupAtRow::<E>::new(INTERACTION_TRACE_IDX, SecureField::zero(), None, is_first);

        // Add checked occurrences to logup sum.
        add_constraints_for_type::<E, IsTypeR>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_R_CHECKED,
        );
        add_constraints_for_type::<E, IsTypeU>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_U_CHECKED,
        );
        add_constraints_for_type::<E, IsTypeINoShift>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        add_constraints_for_type::<E, IsAluImmShift>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_I_SHIFT_CHECKED,
        );
        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range16);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity16);
        let denom: E::EF = lookup_elements.combine(&[range.clone()]);
        let numerator: E::EF = (-multiplicity.clone()).into();
        logup.write_frac(eval, Fraction::new(numerator, denom));
        logup.finalize(eval);
    }
}

fn add_constraints_for_type<
    E: stwo_prover::constraint_framework::EvalAtRow,
    VR: VirtualColumn<1>,
>(
    eval: &mut E,
    trace_eval: &TraceEval<E>,
    lookup_elements: &LookupElements<12>,
    logup: &mut LogupAtRow<E>,
    cols: &[Column],
) {
    let [numerator] = VR::eval(trace_eval);
    for col in cols.iter() {
        // not using trace_eval! macro because it doesn't accept *col as an argument.
        let [value] = trace_eval.column_eval(*col);
        let denom: E::EF = lookup_elements.combine(&[value.clone()]);
        logup.write_frac(eval, Fraction::new(numerator.clone().into(), denom));
    }
}

fn fill_interaction_for_type<VC: VirtualColumn<1>>(
    original_traces: &FinalizedTraces,
    lookup_element: &LookupElements<12>,
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

    use crate::components::{MachineComponent, MachineEval};

    use crate::test_utils::{assert_chip, commit_traces, test_params, CommittedTraces};
    use crate::trace::preprocessed::PreprocessedBuilder;
    use crate::traits::MachineChip;

    use nexus_vm::emulator::HarvardEmulator;
    use stwo_prover::constraint_framework::TraceLocationAllocator;

    use stwo_prover::core::prover::prove;

    pub type Component = MachineComponent<Range16Chip>;

    #[test]
    fn test_range16_chip_success() {
        const LOG_SIZE: u32 = 10; // Traces::MIN_LOG_SIZE makes the test too slow.
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default(), []);

        let mut program_step = ProgramStep::default();
        let mut i = 0;

        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8;

            for col in TYPE_R_CHECKED
                .into_iter()
                .chain(TYPE_I_NO_SHIFT_CHECKED)
                .chain(TYPE_I_SHIFT_CHECKED)
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
                _ => panic!("i must be in 0..3 range"),
            }
            i = (i + 1) % 3;

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &mut program_traces,
                &mut side_note,
            );
        }
        let mut preprocessed_16_rows = PreprocessedBuilder::empty(LOG_SIZE);
        preprocessed_16_rows.fill_is_first();
        preprocessed_16_rows.fill_range16();
        assert_chip::<Range16Chip>(traces, Some(preprocessed_16_rows), None);
    }

    #[test]
    #[should_panic(expected = "ConstraintsNotSatisfied")]
    fn test_range16_chip_fail_out_of_range_release() {
        const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;
        let (config, twiddles) = test_params(LOG_SIZE);
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let mut program_traces = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_traces, &HarvardEmulator::default(), []);
        let mut program_step = ProgramStep::default();
        program_step.step.instruction.ins_type = InstructionType::RType;

        // Write in-range values to ValueA columns.
        for row_idx in 0..traces.num_rows() {
            let b = (row_idx % 16) as u8 + 1; // sometimes out of range
            traces.fill_columns(row_idx, b, Column::OpB14);
            traces.fill_columns(row_idx, true, Column::IsAdd);

            Range16Chip::fill_main_trace(
                &mut traces,
                row_idx,
                &Some(program_step.clone()),
                &mut program_traces,
                &mut side_note,
            );
        }
        let CommittedTraces {
            mut commitment_scheme,
            mut prover_channel,
            lookup_elements,
            preprocessed_trace: _,
            interaction_trace: _,
            program_trace: _,
        } = commit_traces::<Range16Chip>(config, &twiddles, &traces.finalize(), None, None);

        let component = Component::new(
            &mut TraceLocationAllocator::default(),
            MachineEval::<Range16Chip>::new(LOG_SIZE, lookup_elements),
        );

        prove(&[&component], &mut prover_channel, &mut commitment_scheme).unwrap();
    }
}
