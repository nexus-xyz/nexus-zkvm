use nexus_vm::WORD_SIZE;
use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{logup::LookupElements, EvalAtRow},
    core::{
        backend::simd::SimdBackend,
        fields::m31::BaseField,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::machine2::{
    column::Column::{
        self, Reg1Accessed, Reg1Address, Reg1TsPrev, Reg1ValPrev, Reg2Accessed, Reg2Address,
        Reg2TsPrev, Reg2ValPrev, Reg3Accessed, Reg3Address, Reg3TsPrev, Reg3ValPrev,
        ValueAEffective, ValueB, ValueC,
    },
    components::MAX_LOOKUP_TUPLE_SIZE,
    trace::{
        eval::TraceEval,
        regs::{AccessResult, RegisterMemCheckSideNote},
        FromBaseFields, ProgramStep, Traces,
    },
    traits::MachineChip,
};

/// A Chip for register memory checking
///
/// RegisterMemCheckChip needs to be located after all chips that access registers.

pub struct RegisterMemCheckChip;

impl MachineChip for RegisterMemCheckChip {
    /// Fills `Reg{1,2,3}ValPrev` and `Reg{1,2,3}TsPrev` columns
    ///
    /// Assumes other chips have written to `Reg{1,2,3}Accessed` `Reg{1,2,3}Address` `Reg{1,2,3}Value`
    fn fill_main_trace(
        traces: &mut Traces,
        row_idx: usize,
        _vm_step: &ProgramStep,
        side_note: &mut RegisterMemCheckSideNote,
    ) {
        // TODO: consider looking up clk, reg{1,2,3}_cur_ts in the preprocessed trace
        assert!(row_idx < (u32::MAX - 3) as usize / 3);
        let clk = row_idx as u32 + 1;
        let reg1_cur_ts = clk * 3 + 1;
        let reg2_cur_ts = clk * 3 + 2;
        let reg3_cur_ts = clk * 3 + 3;

        // Read inputs to the chip
        let reg1_accessed: [BaseField; 1] = traces.column(row_idx, Reg1Accessed);
        let reg2_accessed: [BaseField; 1] = traces.column(row_idx, Reg2Accessed);
        let reg3_accessed: [BaseField; 1] = traces.column(row_idx, Reg3Accessed);
        let reg1_address: [BaseField; 1] = traces.column(row_idx, Reg1Address);
        let reg2_address: [BaseField; 1] = traces.column(row_idx, Reg2Address);
        let reg3_address: [BaseField; 1] = traces.column(row_idx, Reg3Address);
        let reg1_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueB);
        let reg2_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueC);
        let reg3_value: [BaseField; WORD_SIZE] = traces.column(row_idx, ValueAEffective);

        if !reg1_accessed[0].is_zero() {
            fill_prev_values(
                reg1_address,
                reg1_value,
                side_note,
                reg1_cur_ts,
                Reg1TsPrev,
                Reg1ValPrev,
                traces,
                row_idx,
            );
        }
        if !reg2_accessed[0].is_zero() {
            fill_prev_values(
                reg2_address,
                reg2_value,
                side_note,
                reg2_cur_ts,
                Reg2TsPrev,
                Reg2ValPrev,
                traces,
                row_idx,
            );
        }
        if !reg3_accessed[0].is_zero() {
            fill_prev_values(
                reg3_address,
                reg3_value,
                side_note,
                reg3_cur_ts,
                Reg3TsPrev,
                Reg3ValPrev,
                traces,
                row_idx,
            );
        }

        // TODO: write final register values somewhere
    }
    fn add_constraints<E: EvalAtRow>(
        _eval: &mut E,
        _trace_eval: &TraceEval<E>,
        _lookup_elements: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) {
        // TODO: implement
    }
    fn fill_interaction_trace(
        _original_traces: &Traces,
        _preprocessed_trace: &Traces,
        _lookup_element: &LookupElements<MAX_LOOKUP_TUPLE_SIZE>,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        // TODO: implement
        vec![]
    }
}

fn fill_prev_values(
    reg_address: [BaseField; 1],
    reg_value: [BaseField; WORD_SIZE],
    side_note: &mut RegisterMemCheckSideNote,
    reg_cur_ts: u32,
    dst_ts: Column,
    dst_val: Column,
    traces: &mut Traces,
    row_idx: usize,
) {
    let reg_idx = reg_address[0].0;
    let cur_value = u32::from_base_fields(reg_value);
    let AccessResult {
        prev_timestamp,
        prev_value,
    } = side_note.access(reg_idx, reg_cur_ts, cur_value);
    traces.fill_columns(row_idx, prev_timestamp, dst_ts);
    traces.fill_columns(row_idx, prev_value, dst_val);
}
