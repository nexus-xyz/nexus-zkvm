use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedM31, LOG_N_LANES},
            qm31::PackedSecureField,
            SimdBackend,
        },
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use crate::{
    components::lookups::{
        KeccakBitNotAndLookupElements, KeccakBitRotateLookupElements, KeccakStateLookupElements,
        KeccakXorLookupElements,
    },
    extensions::ComponentTrace,
    trace::sidenote::keccak::{BitOp, RoundLookups},
};

use super::constants::LANE_SIZE;

pub struct RoundLogUpGenerator<'a> {
    pub component_trace: &'a ComponentTrace,
    pub round_lookups: &'a RoundLookups,
}

impl RoundLogUpGenerator<'_> {
    pub fn interaction_trace(
        &self,
        state_lookup_elements: &KeccakStateLookupElements,
        xor_lookup_elements: &KeccakXorLookupElements,
        bit_not_and_lookup_elements: &KeccakBitNotAndLookupElements,
        bit_rotate_lookup_elements: &KeccakBitRotateLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = self.component_trace.log_size;
        let mut logup_gen = LogupTraceGenerator::new(log_size);

        let original_trace = &self.component_trace.original_trace;
        let preprocessed_trace = &self.component_trace.preprocessed_trace;

        for ([a, b, c], op) in &self.round_lookups.bitwise_lookups {
            let a = &original_trace[*a..*a + LANE_SIZE];
            let b = &original_trace[*b..*b + LANE_SIZE];
            let c = &original_trace[*c..*c + LANE_SIZE];
            if let BitOp::Rotation(r) = *op {
                self.rotation_logup_gen(&mut logup_gen, bit_rotate_lookup_elements, r, a, b, c);
            } else {
                self.bitwise_logup_gen(
                    &mut logup_gen,
                    xor_lookup_elements,
                    bit_not_and_lookup_elements,
                    *op,
                    a,
                    b,
                    c,
                );
            }
        }
        // ι step
        let (a, xor_rc) = self.round_lookups.xor_rc_lookup;
        let a = &original_trace[a..a + LANE_SIZE];
        let rc = &preprocessed_trace[..LANE_SIZE];
        let xor_rc = &original_trace[xor_rc..xor_rc + LANE_SIZE];
        self.bitwise_logup_gen(
            &mut logup_gen,
            xor_lookup_elements,
            bit_not_and_lookup_elements,
            BitOp::Xor,
            a,
            rc,
            xor_rc,
        );

        let input_state = &original_trace[..25 * LANE_SIZE];
        let output_state: Vec<&BaseColumn> = self
            .round_lookups
            .output_state_lookup
            .iter()
            .flat_map(|&i| &original_trace[i..i + LANE_SIZE])
            .collect();
        let is_padding = original_trace.last().expect("trace must be non-empty");
        self.state_logup_gen(
            &mut logup_gen,
            state_lookup_elements,
            input_state,
            &output_state,
            is_padding,
        );

        logup_gen.finalize_last()
    }

    fn bitwise_logup_gen(
        &self,
        logup_gen: &mut LogupTraceGenerator,
        xor_lookup_elements: &KeccakXorLookupElements,
        bit_not_and_lookup_elements: &KeccakBitNotAndLookupElements,
        bit_op: BitOp,
        a: &[BaseColumn],
        b: &[BaseColumn],
        c: &[BaseColumn],
    ) {
        for i in (0..LANE_SIZE).step_by(2) {
            let mut logup_col_gen = logup_gen.new_col();
            for vec_idx in 0..(1 << (self.component_trace.log_size - LOG_N_LANES)) {
                let xor1 = {
                    let a = a[i].data[vec_idx];
                    let b = b[i].data[vec_idx];
                    let c = c[i].data[vec_idx];
                    [a, b, c]
                };
                let xor2 = {
                    let a = a[i + 1].data[vec_idx];
                    let b = b[i + 1].data[vec_idx];
                    let c = c[i + 1].data[vec_idx];
                    [a, b, c]
                };
                let (p0, p1) = match bit_op {
                    BitOp::Xor => {
                        let p0: PackedSecureField = xor_lookup_elements.combine(&xor1);
                        let p1: PackedSecureField = xor_lookup_elements.combine(&xor2);
                        (p0, p1)
                    }
                    BitOp::BitNotAnd => {
                        let p0: PackedSecureField = bit_not_and_lookup_elements.combine(&xor1);
                        let p1: PackedSecureField = bit_not_and_lookup_elements.combine(&xor2);
                        (p0, p1)
                    }
                    _ => panic!("invalid bit operation"),
                };

                logup_col_gen.write_frac(vec_idx, p0 + p1, p0 * p1);
            }
            logup_col_gen.finalize_col();
        }
    }

    fn rotation_logup_gen(
        &self,
        logup_gen: &mut LogupTraceGenerator,
        lookup_elements: &KeccakBitRotateLookupElements,
        r: u32,
        a: &[BaseColumn],
        bytes_high: &[BaseColumn],
        bytes_low: &[BaseColumn],
    ) {
        let shift = BaseField::from(r).into();
        for i in (0..LANE_SIZE).step_by(2) {
            let mut logup_col_gen = logup_gen.new_col();
            for vec_idx in 0..(1 << (self.component_trace.log_size - LOG_N_LANES)) {
                let p0: PackedSecureField = {
                    let input = a[i].data[vec_idx];
                    let bytes_high = bytes_high[i].data[vec_idx];
                    let bytes_low = bytes_low[i].data[vec_idx];
                    lookup_elements.combine(&[input, shift, bytes_high, bytes_low])
                };
                let p1: PackedSecureField = {
                    let input = a[i + 1].data[vec_idx];
                    let bytes_high = bytes_high[i + 1].data[vec_idx];
                    let bytes_low = bytes_low[i + 1].data[vec_idx];
                    lookup_elements.combine(&[input, shift, bytes_high, bytes_low])
                };

                logup_col_gen.write_frac(vec_idx, p0 + p1, p0 * p1);
            }
            logup_col_gen.finalize_col();
        }
    }

    fn state_logup_gen(
        &self,
        logup_gen: &mut LogupTraceGenerator,
        lookup_elements: &KeccakStateLookupElements,
        input_state: &[BaseColumn],
        output_state: &[&BaseColumn],
        is_padding: &BaseColumn,
    ) {
        let mut logup_col_gen = logup_gen.new_col();
        for vec_idx in 0..(1 << (self.component_trace.log_size - LOG_N_LANES)) {
            let p0: PackedSecureField = {
                let tuple: Vec<PackedM31> =
                    input_state.iter().map(|col| col.data[vec_idx]).collect();
                lookup_elements.combine(&tuple)
            };
            let p1: PackedSecureField = {
                let tuple: Vec<PackedM31> =
                    output_state.iter().map(|col| col.data[vec_idx]).collect();
                lookup_elements.combine(&tuple)
            };
            let is_padding: PackedSecureField = is_padding.data[vec_idx].into();
            let numerator = is_padding * (p1 - p0) + p0 - p1;
            logup_col_gen.write_frac(vec_idx, numerator, p0 * p1);
        }
        logup_col_gen.finalize_col();
    }
}
