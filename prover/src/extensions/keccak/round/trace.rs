#![allow(clippy::needless_range_loop)]

use std::simd::u32x16;

use num_traits::{One, Zero};
use stwo::{
    core::fields::m31::BaseField,
    prover::backend::simd::{
        column::BaseColumn,
        m31::{PackedBaseField, LOG_N_LANES},
    },
};

use super::{
    constants::{LANE_SIZE, RC, ROTATIONS, ROUNDS},
    keccak_round,
};
use crate::{
    extensions::{
        keccak::{bit_rotate::BitRotateAccumulator, bitwise_table::BitwiseAccumulator},
        trace::ComponentTrace,
    },
    trace::sidenote::keccak::{BitOp, KeccakSideNote, RoundLookups},
};

struct TraceBuilder<'a> {
    trace: Vec<Vec<u32x16>>,
    round_constants: [Vec<u32x16>; LANE_SIZE],
    log_size: u32,
    xor_accum: &'a mut BitwiseAccumulator,
    bit_not_and_accum: &'a mut BitwiseAccumulator,
    bit_rotate_accum: &'a mut BitRotateAccumulator,
    side_note_lookups: &'a mut Vec<RoundLookups>,
    round_lookups: RoundLookups,
}

impl<'b: 'a, 'a> TraceBuilder<'a> {
    fn new(
        log_n_instances: u32,
        offset: usize,
        rounds: usize,
        side_note: &'b mut KeccakSideNote,
    ) -> Self {
        let round_constants = round_constants_to_simd(log_n_instances, offset, rounds);
        let log_size = log_n_instances + rounds.ilog2();

        let xor_accum = side_note.xor_accum.get_or_insert_default();
        let bit_not_and_accum = side_note.bit_not_and_accum.get_or_insert_default();
        let bit_rotate_accum = &mut side_note.bit_rotate_accum;
        let side_note_lookups = &mut side_note.round_lookups;
        Self {
            log_size,
            trace: Default::default(),
            round_constants,
            xor_accum,
            bit_not_and_accum,
            bit_rotate_accum,
            side_note_lookups,
            round_lookups: Default::default(),
        }
    }

    fn allocate_lanes(&mut self, mut lanes: impl AsMut<[Vec<u32x16>]>) -> Vec<usize> {
        let mut allocated = vec![];
        for lanes in lanes.as_mut().chunks_exact_mut(LANE_SIZE) {
            allocated.push(self.trace.len());
            lanes
                .iter_mut()
                .for_each(|lane| self.trace.push(std::mem::take(lane)));
        }
        allocated
    }

    fn xor2(&mut self, a: usize, b: usize) -> usize {
        let mut xor: [_; LANE_SIZE] = std::array::from_fn(|_idx| Vec::new());

        for i in 0..LANE_SIZE {
            xor[i] = self.trace[a + i]
                .iter()
                .zip(&self.trace[b + i])
                .map(|(a, b)| {
                    self.xor_accum.add_input(*a, *b);
                    a ^ b
                })
                .collect();
        }

        let xor = self.allocate_lanes(&mut xor)[0];
        self.round_lookups
            .bitwise_lookups
            .push(([a, b, xor], BitOp::Xor));
        xor
    }

    fn xor2_rc(&mut self, a: usize) -> usize {
        let mut xor: [_; LANE_SIZE] = std::array::from_fn(|_idx| Vec::new());

        for i in 0..LANE_SIZE {
            xor[i] = self.trace[a + i]
                .iter()
                .zip(&self.round_constants[i])
                .map(|(a, b)| {
                    self.xor_accum.add_input(*a, *b);
                    a ^ b
                })
                .collect();
        }

        let xor_rc = self.allocate_lanes(&mut xor)[0];
        self.round_lookups.xor_rc_lookup = (a, xor_rc);
        xor_rc
    }

    fn bitwise_not_and(&mut self, a: usize, b: usize) -> usize {
        let mut result: [_; LANE_SIZE] = std::array::from_fn(|_idx| Vec::new());
        for i in 0..LANE_SIZE {
            result[i] = self.trace[a + i]
                .iter()
                .zip(&self.trace[b + i])
                .map(|(a, b)| {
                    self.bit_not_and_accum.add_input(*a, *b);
                    !*a & b
                })
                .collect();
        }

        let result = self.allocate_lanes(&mut result)[0];
        self.round_lookups
            .bitwise_lookups
            .push(([a, b, result], BitOp::BitNotAnd));
        result
    }

    fn rotate_left(&mut self, a: usize, r: u32) -> usize {
        if r == 0 {
            return a;
        }

        let bits = r % 8;
        let rotate = (r / 8) as i8;

        let mut bytes_low: [_; LANE_SIZE] = std::array::from_fn(|_idx| Vec::new());
        let mut bytes_high = bytes_low.clone();
        let mut out = bytes_low.clone();

        for i in 0..LANE_SIZE {
            let col = &self.trace[a + i];
            bytes_low[i] = col
                .iter()
                .map(|b| {
                    self.bit_rotate_accum.add_rotation(*b, bits);
                    (b << bits) & u32x16::splat((1 << 8) - 1)
                })
                .collect();
            bytes_high[i] = col.iter().map(|b| b >> (8 - bits)).collect();
        }

        for i in 0..LANE_SIZE {
            let i = i as i8;
            let low = (i - rotate) & 0b111;
            let high = (i - rotate + 7) & 0b111;
            out[i as usize] = bytes_low[low as usize]
                .iter()
                .zip(&bytes_high[high as usize])
                .map(|(a, b)| a + b)
                .collect();
        }

        let low = self.allocate_lanes(bytes_low)[0];
        let high = self.allocate_lanes(bytes_high)[0];
        self.round_lookups
            .bitwise_lookups
            .push(([a, high, low], BitOp::Rotation(bits)));

        self.allocate_lanes(&mut out)[0]
    }

    fn output_state_lookup(&mut self, output_state: Vec<usize>) {
        self.round_lookups.output_state_lookup = output_state;
    }

    fn into_component_trace(self) -> ComponentTrace {
        macro_rules! base_column_from_simd {
            ($trace:expr) => {
                $trace
                    .into_iter()
                    .map(|col| {
                        let base_col = BaseColumn::from_simd(
                            col.into_iter()
                                .map(|v| unsafe { PackedBaseField::from_simd_unchecked(v) })
                                .collect(),
                        );
                        base_col
                    })
                    .collect()
            };
        }
        let round_lookups = self.round_lookups;
        self.side_note_lookups.push(round_lookups);

        ComponentTrace {
            log_size: self.log_size,
            preprocessed_trace: base_column_from_simd!(self.round_constants),
            original_trace: base_column_from_simd!(self.trace),
        }
    }
}

pub fn round_constants_to_simd(
    log_n_instances: u32,
    offset: usize,
    rounds: usize,
) -> [Vec<u32x16>; LANE_SIZE] {
    let rc_iter = RC[offset..offset + rounds]
        .iter()
        .copied()
        .cycle()
        .take((1 << log_n_instances) * rounds);
    let mut rc_bytes = vec![vec![]; LANE_SIZE];

    for rc in rc_iter.map(u64::to_le_bytes) {
        for (i, byte) in rc.iter().enumerate() {
            rc_bytes[i].push(*byte as u32);
        }
    }
    rc_bytes
        .into_iter()
        .map(|col| {
            col.iter()
                .copied()
                .array_chunks()
                .map(u32x16::from_array)
                .collect()
        })
        .collect::<Vec<Vec<u32x16>>>()
        .try_into()
        .expect("lane size mismatch")
}

pub fn convert_input_to_simd(
    inputs: &[[u64; 25]],
    offset: usize,
    rounds: usize,
) -> (Vec<Vec<u32x16>>, Vec<[u64; 25]>) {
    assert!(rounds.is_power_of_two());

    let mut trace = vec![vec![]; 25 * LANE_SIZE];
    let round_inputs = inputs.iter().flat_map(|state| {
        let mut state = *state;
        (0..=rounds).map(move |i| {
            // flag rows that should be pushed to the remainder instead of trace
            if i == rounds {
                assert!(i + offset <= ROUNDS);
                (true, state)
            } else {
                let next = state;
                keccak_round(&mut state, RC[i + offset]);

                (false, next)
            }
        })
    });

    // pad for simd
    let num_rows = (inputs.len() * rounds).next_multiple_of(1 << LOG_N_LANES);
    let mut rem = vec![];

    for (skip_row, round_input) in round_inputs
        .chain(std::iter::repeat_with(|| (false, [0u64; 25])))
        .take(num_rows + inputs.len())
    {
        if skip_row {
            rem.push(round_input);
            continue;
        }
        for (col, byte) in round_input
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .enumerate()
        {
            trace[col].push(byte as u32);
        }
    }
    let trace = trace
        .into_iter()
        .map(|col| {
            col.iter()
                .copied()
                .array_chunks()
                .map(u32x16::from_array)
                .collect()
        })
        .collect();
    (trace, rem)
}

pub fn generate_round_component_trace(
    log_n_instances: u32,
    inputs: Vec<Vec<u32x16>>,
    offset: usize,
    rounds: usize,
    real_rows: usize,
    side_note: &mut KeccakSideNote,
) -> ComponentTrace {
    let mut builder = TraceBuilder::new(log_n_instances, offset, rounds, side_note);
    let log_size = builder.log_size;
    let inputs = pad_input(inputs, log_size);

    // θ step
    // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
    // D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
    // A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
    let mut a = builder.allocate_lanes(inputs);
    let mut c = Vec::new();
    for x in 0..5 {
        let mut xor = a[x];
        for i in 1..5 {
            xor = builder.xor2(xor, a[x + i * 5]);
        }
        c.push(xor);
    }

    let mut d = Vec::new();
    for x in 0..5 {
        let rot_c = builder.rotate_left(c[(x + 1) % 5], 1);
        let xor = builder.xor2(c[(x + 4) % 5], rot_c);
        d.push(xor);
    }
    for x in 0..5 {
        for y in 0..5 {
            a[x + y * 5] = builder.xor2(a[x + y * 5], d[x]);
        }
    }

    // ρ and π steps
    // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
    let mut b = [0usize; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + ((2 * x + 3 * y) % 5) * 5] =
                builder.rotate_left(a[x + y * 5], ROTATIONS[x + y * 5] as u32);
        }
    }

    // χ step
    // A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
    for x in 0..5 {
        for y in 0..5 {
            let rhs = builder.bitwise_not_and(b[(x + 1) % 5 + y * 5], b[(x + 2) % 5 + y * 5]);
            a[x + y * 5] = builder.xor2(b[x + y * 5], rhs);
        }
    }

    a[0] = builder.xor2_rc(a[0]);
    let output_state = a;
    builder.output_state_lookup(output_state);
    let mut component_trace = builder.into_component_trace();

    component_trace
        .preprocessed_trace
        .push(preprocessed_is_last_column(log_size));
    component_trace
        .original_trace
        .push(get_is_padding_base_column(log_size, real_rows));
    component_trace
}

pub(crate) fn get_is_padding_base_column(log_size: u32, real_rows: usize) -> BaseColumn {
    let len = 1 << log_size;
    (0..len)
        .map(|i| {
            if i < real_rows {
                BaseField::zero()
            } else {
                BaseField::one()
            }
        })
        .collect()
}

pub(crate) fn preprocessed_is_last_column(log_size: u32) -> BaseColumn {
    let mut col = vec![BaseField::zero(); 1 << log_size];
    *col.last_mut().expect("len is non-zero") = BaseField::one();

    BaseColumn::from_iter(col)
}

fn pad_input(input: Vec<Vec<u32x16>>, log_size: u32) -> Vec<Vec<u32x16>> {
    let mut input = input;
    for col in &mut input {
        col.resize(1 << (log_size - LOG_N_LANES), u32x16::splat(0));
    }

    input
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    use super::*;

    #[test]
    fn empty_input_padding() {
        let (input, rem) = convert_input_to_simd(&[], 0, 1 << 4);
        assert!(rem.is_empty());
        let padded = pad_input(input, LOG_N_LANES);

        assert_eq!(padded[0].len(), 1);
    }

    #[test]
    fn round_initial_states_match() {
        let mut rng = ChaCha12Rng::from_seed(Default::default());
        let inputs: Vec<[u64; 25]> =
            std::iter::repeat_with(|| std::array::from_fn(|_idx| rng.next_u64()))
                .take(20)
                .collect();

        let (_, rem) = convert_input_to_simd(&inputs, 0, 1 << 4);

        let expected: Vec<[u64; 25]> = inputs
            .iter()
            .map(|input| {
                let mut input = *input;
                for &rc in &RC[..1 << 4] {
                    keccak_round(&mut input, rc);
                }
                input
            })
            .collect();

        assert_eq!(rem.len(), expected.len());
        for (state, expected) in rem.into_iter().zip(expected) {
            assert_eq!(state, expected);
        }
    }
}
