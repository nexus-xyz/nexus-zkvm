use stwo::{
    core::{
        air::Component,
        fields::{m31::BaseField, qm31::SecureField},
        poly::circle::CanonicCoset,
        ColumnVec,
    },
    prover::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ComponentProver,
    },
};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::{constants::LANE_SIZE, eval::KeccakRoundEval, interaction_trace::RoundLogUpGenerator};
use crate::{
    components::{
        lookups::{
            KeccakBitNotAndLookupElements, KeccakBitRotateLookupElements,
            KeccakStateLookupElements, KeccakXorLookupElements,
        },
        AllLookupElements,
    },
    extensions::{
        keccak::round::trace::{
            convert_input_to_simd, generate_round_component_trace, preprocessed_is_last_column,
            round_constants_to_simd,
        },
        BuiltInExtension, ComponentTrace,
    },
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct KeccakRound {
    pub(crate) index: usize,
    pub(crate) rounds: usize,
    pub(crate) offset: usize,
}

impl BuiltInExtension for KeccakRound {
    type Eval = KeccakRoundEval;

    fn generate_preprocessed_trace(
        &self,
        log_size: u32,
        _: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let log_n_instances = log_size - self.rounds.ilog2();
        let domain = CanonicCoset::new(log_size).circle_domain();

        let rc = round_constants_to_simd(log_n_instances, self.offset, self.rounds);
        rc.into_iter()
            .map(|eval| {
                BaseColumn::from_simd(
                    eval.into_iter()
                        .map(|v| unsafe { PackedBaseField::from_simd_unchecked(v) })
                        .collect(),
                )
            })
            .chain(std::iter::once(preprocessed_is_last_column(log_size)))
            .map(|eval| {
                CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(domain, eval)
            })
            .collect()
    }

    fn generate_component_trace(
        &self,
        log_size: u32,
        _: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace {
        let log_n_instances = log_size - self.rounds.ilog2();

        let inputs = &side_note.keccak.inputs;
        let real_rows = inputs.len() * self.rounds;
        let (states, next_inputs) = convert_input_to_simd(inputs, self.offset, self.rounds);
        side_note.keccak.inputs = next_inputs;

        generate_round_component_trace(
            log_n_instances,
            states,
            self.offset,
            self.rounds,
            real_rows,
            &mut side_note.keccak,
        )
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
        let state_lookup_elements: &KeccakStateLookupElements = lookup_elements.as_ref();
        let xor_lookup_elements: &KeccakXorLookupElements = lookup_elements.as_ref();
        let bit_not_and_lookup_elements: &KeccakBitNotAndLookupElements = lookup_elements.as_ref();
        let bit_rotate_lookup_elements: &KeccakBitRotateLookupElements = lookup_elements.as_ref();
        RoundLogUpGenerator {
            component_trace: &component_trace,
            round_lookups: &side_note.keccak.round_lookups[self.index],
        }
        .interaction_trace(
            state_lookup_elements,
            xor_lookup_elements,
            bit_not_and_lookup_elements,
            bit_rotate_lookup_elements,
        )
    }

    fn compute_log_size(&self, side_note: &SideNote) -> u32 {
        assert!(self.rounds.is_power_of_two());
        let keccak_side_note = &side_note.keccak;
        let input_len = keccak_side_note.inputs.len();

        let trace_len = input_len * self.rounds;
        let log_size = trace_len.next_power_of_two().ilog2();
        log_size.max(LOG_N_LANES)
    }

    fn preprocessed_trace_sizes(log_size: u32) -> Vec<u32> {
        // round constants + is_last
        vec![log_size; LANE_SIZE + 1]
    }

    fn to_component_prover(
        &self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend>> {
        let state_lookup_elements: &KeccakStateLookupElements = lookup_elements.as_ref();
        let xor_lookup_elements: &KeccakXorLookupElements = lookup_elements.as_ref();
        let bit_not_and_lookup_elements: &KeccakBitNotAndLookupElements = lookup_elements.as_ref();
        let bit_rotate_lookup_elements: &KeccakBitRotateLookupElements = lookup_elements.as_ref();
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            KeccakRoundEval {
                index: self.index,
                log_size,
                state_lookup_elements: state_lookup_elements.clone(),
                xor_lookup_elements: xor_lookup_elements.clone(),
                bit_not_and_lookup_elements: bit_not_and_lookup_elements.clone(),
                bit_rotate_lookup_elements: bit_rotate_lookup_elements.clone(),
            },
            claimed_sum,
        ))
    }

    fn to_component(
        &self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component> {
        let state_lookup_elements: &KeccakStateLookupElements = lookup_elements.as_ref();
        let xor_lookup_elements: &KeccakXorLookupElements = lookup_elements.as_ref();
        let bit_not_and_lookup_elements: &KeccakBitNotAndLookupElements = lookup_elements.as_ref();
        let bit_rotate_lookup_elements: &KeccakBitRotateLookupElements = lookup_elements.as_ref();
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            KeccakRoundEval {
                index: self.index,
                log_size,
                state_lookup_elements: state_lookup_elements.clone(),
                xor_lookup_elements: xor_lookup_elements.clone(),
                bit_not_and_lookup_elements: bit_not_and_lookup_elements.clone(),
                bit_rotate_lookup_elements: bit_rotate_lookup_elements.clone(),
            },
            claimed_sum,
        ))
    }
}
