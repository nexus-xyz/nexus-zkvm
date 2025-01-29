// This file contains range-checking values for 0..=7.

use nexus_vm::{
    riscv::{BuiltinOpcode, InstructionType},
    WORD_SIZE,
};
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
        Column::{self, Multiplicity8, OpC1_3, OpC5_7, OpC8_10},
        PreprocessedColumn::{self, IsFirst, Range8},
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, TraceEval},
        program_trace::{ProgramTraces, ProgramTracesBuilder},
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{IsTypeB, IsTypeINoShift, IsTypeJ, VirtualColumn, VirtualColumnForSum},
};

/// A flag for Helper1[0] to be checked against 0..=7.
struct Helper1MsbChecked;

impl VirtualColumnForSum for Helper1MsbChecked {
    fn columns() -> &'static [Column] {
        &[Column::IsSll, Column::IsSrl, Column::IsSra]
    }
}

/// A Chip for range-checking values for 0..=7
///
/// Range8Chip needs to be located at the end of the chip composition together with the other range check chips

pub struct Range8Chip;

const TYPE_I_NO_SHIFT_CHECKED: [Column; 1] = [OpC8_10];
const TYPE_J_CHECKED: [Column; 2] = [OpC1_3, OpC8_10];
const TYPE_B_CHECKED: [Column; 2] = [OpC5_7, OpC8_10];

impl MachineChip for Range8Chip {
    /// Increments Multiplicity8 for every number checked
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        step: &Option<ProgramStep>,
        _program_traces: &mut ProgramTracesBuilder,
        _side_note: &mut SideNote,
    ) {
        let step = match step {
            None => return, // Nothing to check in padding rows
            Some(step) => step,
        };
        // Add multiplicities for Helper1[0] in case of SLL, SLLI, SRL SRLI, SRA and SRAI
        if matches!(
            step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SLL)
                | Some(BuiltinOpcode::SLLI)
                | Some(BuiltinOpcode::SRL)
                | Some(BuiltinOpcode::SRLI)
                | Some(BuiltinOpcode::SRA)
                | Some(BuiltinOpcode::SRAI)
        ) {
            let [helper1_0, _, _, _] = traces.column(row_idx, Column::Helper1);
            fill_main_elm(helper1_0, traces);
        }

        fill_main_for_type::<IsTypeINoShift>(
            traces,
            row_idx,
            step,
            InstructionType::IType,
            &TYPE_I_NO_SHIFT_CHECKED,
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
    }

    /// Fills the whole interaction trace in one-go using SIMD in the stwo-usual way
    ///
    /// data[vec_row] contains sixteen rows. A single write_frac() adds sixteen numbers.
    fn fill_interaction_trace(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let mut logup_trace_gen = LogupTraceGenerator::new(original_traces.log_size());

        fill_interaction_for_type::<IsTypeINoShift>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        fill_interaction_for_type::<IsTypeJ>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_J_CHECKED,
        );
        fill_interaction_for_type::<IsTypeB>(
            original_traces,
            lookup_element,
            &mut logup_trace_gen,
            &TYPE_B_CHECKED,
        );

        // Fill the interaction trace for Helper1[0] in case of SLL, SRL and SRA
        let [value_basecolumn, _, _, _]: [&BaseColumn; WORD_SIZE] =
            original_traces.get_base_column(Column::Helper1);
        let log_size = original_traces.log_size();
        // TODO: we can deal with two limbs at a time.
        let mut logup_col_gen = logup_trace_gen.new_col();
        // vec_row is row_idx divided by 16. Because SIMD.
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let checked_tuple = vec![value_basecolumn.data[vec_row]];
            let denom = lookup_element.combine(&checked_tuple);
            let [is_type] = Helper1MsbChecked::read_from_finalized_traces(original_traces, vec_row);
            logup_col_gen.write_frac(vec_row, is_type.into(), denom);
        }
        logup_col_gen.finalize_col();

        // Subtract looked up multiplicites from logup sum.
        let range_basecolumn: [&BaseColumn; Range8.size()] =
            preprocessed_traces.get_preprocessed_base_column(Range8);
        let multiplicity_basecolumn: [&BaseColumn; Multiplicity8.size()] =
            original_traces.get_base_column(Multiplicity8);
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

        add_constraints_for_type::<E, IsTypeINoShift>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_I_NO_SHIFT_CHECKED,
        );
        add_constraints_for_type::<E, IsTypeJ>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_J_CHECKED,
        );
        add_constraints_for_type::<E, IsTypeB>(
            eval,
            trace_eval,
            lookup_elements,
            &mut logup,
            &TYPE_B_CHECKED,
        );

        // Add checked multiplicities for Helper1[0] in case of SLL, SRL and SRA
        let [numerator] = Helper1MsbChecked::eval(trace_eval);
        let [value, _, _, _] = trace_eval.column_eval(Column::Helper1);
        let denom: E::EF = lookup_elements.combine(&[value.clone()]);
        logup.write_frac(eval, Fraction::new(numerator.clone().into(), denom));

        // Subtract looked up multiplicites from logup sum.
        let [range] = preprocessed_trace_eval!(trace_eval, Range8);
        let [multiplicity] = trace_eval!(trace_eval, Multiplicity8);
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
    step: &ProgramStep,
    instruction_type: InstructionType,
    columns: &[Column],
) {
    let step_is_of_type = step.step.instruction.ins_type == instruction_type;

    // For some reasons ECALL and EBREAK are considered to be IType, but they don't contain immediate values to range-check.
    if matches!(
        step.step.instruction.opcode.builtin(),
        Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK)
    ) {
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
    assert!(checked < 8, "value is out of range {}", checked);
    let multiplicity_col: [&mut BaseField; 1] = traces.column_mut(checked as usize, Multiplicity8);
    *multiplicity_col[0] += BaseField::one();
    // Detect overflow: there's a soundness problem if this chip is used to check 2^31-1 numbers or more.
    assert_ne!(*multiplicity_col[0], BaseField::zero());
}
