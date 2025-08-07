use num_traits::Zero;
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            qm31::PackedSecureField,
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};

use nexus_common::constants::WORD_SIZE_HALVED;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use super::PermutationMemoryCheckEval;
use crate::{
    components::lookups::{KeccakStateLookupElements, LoadStoreLookupElements},
    extensions::ComponentTrace,
    trace::sidenote::SideNote,
};

pub(super) use crate::extensions::keccak::round::trace::{
    get_is_padding_base_column, preprocessed_is_last_column,
};

pub fn generate_keccak_mem_check_trace(log_size: u32, side_note: &SideNote) -> ComponentTrace {
    let state_size = PermutationMemoryCheckEval::STATE_SIZE;
    // [in_state, out_state, addresses, prev_ts, next_ts, addr_carries, ts_carries]
    let mut original_trace =
        vec![
            vec![BaseField::zero(); 1 << log_size];
            state_size * 2 + state_size * WORD_SIZE_HALVED * 3 + state_size + state_size
        ];

    for (row, &input) in side_note.keccak.inputs.iter().enumerate() {
        let mut output = input;
        tiny_keccak::keccakf(&mut output);

        let (input_output_trace, rem) = original_trace.as_mut_slice().split_at_mut(state_size * 2);
        for (col, byte) in input.into_iter().flat_map(u64::to_le_bytes).enumerate() {
            input_output_trace[col][row] = BaseField::from(byte as u32);
        }
        for (col, byte) in output.into_iter().flat_map(u64::to_le_bytes).enumerate() {
            input_output_trace[col + PermutationMemoryCheckEval::STATE_SIZE][row] =
                BaseField::from(byte as u32);
        }

        let (addr_trace, rem) = rem.split_at_mut(state_size * WORD_SIZE_HALVED);

        let mask = (1 << 16) - 1;
        let shift = 16;
        let addr = side_note.keccak.addresses[row];
        for (col, limb) in (0..state_size)
            .flat_map(|i| {
                let addr = addr + i as u32;
                [addr & mask, (addr >> shift) & mask]
            })
            .enumerate()
        {
            addr_trace[col][row] = limb.into();
        }

        let timestamps = &side_note.keccak.timestamps[row];
        // prev ts
        let (ts_trace, rem) = rem.split_at_mut(state_size * WORD_SIZE_HALVED);
        for (col, limb) in timestamps
            .iter()
            .copied()
            .flat_map(|ts| [ts & mask, (ts >> shift) & mask])
            .enumerate()
        {
            ts_trace[col][row] = limb.into();
        }

        // next ts
        let (ts_trace, rem) = rem.split_at_mut(state_size * WORD_SIZE_HALVED);
        for (col, limb) in timestamps
            .iter()
            .copied()
            .flat_map(|ts| {
                let ts = ts + 1;
                [ts & mask, (ts >> shift) & mask]
            })
            .enumerate()
        {
            ts_trace[col][row] = limb.into();
        }
        // addr carries
        let (addr_carries_trace, rem) = rem.split_at_mut(state_size);
        for (col, carry) in (0..state_size)
            .map(|i| (addr + i as u32) & mask == mask)
            .enumerate()
        {
            addr_carries_trace[col][row] = BaseField::from(u32::from(carry));
        }

        // ts carries
        let (ts_carries_trace, _) = rem.split_at_mut(state_size);
        for (col, carry) in timestamps.iter().map(|ts| ts & mask == mask).enumerate() {
            ts_carries_trace[col][row] = BaseField::from(u32::from(carry));
        }
    }
    let real_rows = side_note.keccak.inputs.len();
    let is_padding = get_is_padding_base_column(log_size, real_rows);
    let mut original_trace: Vec<BaseColumn> = original_trace
        .into_iter()
        .map(BaseColumn::from_iter)
        .collect();
    original_trace.push(is_padding);
    let preprocessed_trace = vec![preprocessed_is_last_column(log_size)];

    ComponentTrace {
        log_size,
        preprocessed_trace,
        original_trace,
    }
}

pub(super) struct MemoryCheckLogUpGenerator<'a> {
    pub(super) component_trace: &'a ComponentTrace,
}

impl MemoryCheckLogUpGenerator<'_> {
    pub fn interaction_trace(
        &self,
        state_lookup_elements: &KeccakStateLookupElements,
        memory_lookup_elements: &LoadStoreLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let state_size = PermutationMemoryCheckEval::STATE_SIZE;
        let log_size = self.component_trace.log_size;
        let mut logup_gen = LogupTraceGenerator::new(log_size);

        let original_trace = self.component_trace.original_trace.as_slice();

        let (input_state, trace) = original_trace.split_at(state_size);
        let (output_state, trace) = trace.split_at(state_size);

        let (addrs, trace) = trace.split_at(state_size * WORD_SIZE_HALVED);
        let (prev_ts, trace) = trace.split_at(state_size * WORD_SIZE_HALVED);
        let (next_ts, rem) = trace.split_at(state_size * WORD_SIZE_HALVED);

        // skip carries
        let (_, rem) = rem.split_at(state_size * 2);

        assert_eq!(rem.len(), 1);
        let is_padding = &rem[0];

        self.state_logup_gen(
            &mut logup_gen,
            state_lookup_elements,
            input_state,
            output_state,
            is_padding,
        );
        self.memory_logup_gen(
            &mut logup_gen,
            memory_lookup_elements,
            input_state,
            output_state,
            addrs,
            prev_ts,
            next_ts,
            is_padding,
        );
        logup_gen.finalize_last()
    }

    fn state_logup_gen(
        &self,
        logup_gen: &mut LogupTraceGenerator,
        lookup_elements: &KeccakStateLookupElements,
        input_state: &[BaseColumn],
        output_state: &[BaseColumn],
        is_padding: &BaseColumn,
    ) {
        let mut logup_col_gen = logup_gen.new_col();
        for vec_idx in 0..(1 << (self.component_trace.log_size - LOG_N_LANES)) {
            let p0: PackedSecureField = {
                let tuple: Vec<PackedBaseField> =
                    input_state.iter().map(|col| col.data[vec_idx]).collect();
                lookup_elements.combine(&tuple)
            };
            let p1: PackedSecureField = {
                let tuple: Vec<PackedBaseField> =
                    output_state.iter().map(|col| col.data[vec_idx]).collect();
                lookup_elements.combine(&tuple)
            };
            let is_padding: PackedSecureField = is_padding.data[vec_idx].into();
            let numerator = is_padding * (p0 - p1) + p1 - p0;
            logup_col_gen.write_frac(vec_idx, numerator, p0 * p1);
        }
        logup_col_gen.finalize_col();
    }

    fn memory_logup_gen(
        &self,
        logup_gen: &mut LogupTraceGenerator,
        memory_lookup_elements: &LoadStoreLookupElements,
        input_state: &[BaseColumn],
        output_state: &[BaseColumn],
        addrs: &[BaseColumn],
        prev_ts: &[BaseColumn],
        next_ts: &[BaseColumn],
        is_padding: &BaseColumn,
    ) {
        for i in 0..PermutationMemoryCheckEval::STATE_SIZE {
            let j = i * WORD_SIZE_HALVED;
            let mut logup_col_gen = logup_gen.new_col();
            for vec_idx in 0..(1 << (self.component_trace.log_size - LOG_N_LANES)) {
                let prev_val = &input_state[i];
                let next_val = &output_state[i];
                let addr = &addrs[j..j + WORD_SIZE_HALVED];

                let p0: PackedSecureField = {
                    let prev_ts = &prev_ts[j..j + WORD_SIZE_HALVED];
                    let tuple: Vec<PackedBaseField> = addr
                        .iter()
                        .chain(std::iter::once(prev_val))
                        .chain(prev_ts)
                        .map(|col| col.data[vec_idx])
                        .collect();
                    memory_lookup_elements.combine(&tuple)
                };

                let p1: PackedSecureField = {
                    let next_ts = &next_ts[j..j + WORD_SIZE_HALVED];
                    let tuple: Vec<PackedBaseField> = addr
                        .iter()
                        .chain(std::iter::once(next_val))
                        .chain(next_ts)
                        .map(|col| col.data[vec_idx])
                        .collect();
                    memory_lookup_elements.combine(&tuple)
                };
                let is_padding: PackedSecureField = is_padding.data[vec_idx].into();
                let numerator = is_padding * (p1 - p0) + p0 - p1;
                logup_col_gen.write_frac(vec_idx, numerator, p0 * p1);
            }

            logup_col_gen.finalize_col();
        }
    }
}
