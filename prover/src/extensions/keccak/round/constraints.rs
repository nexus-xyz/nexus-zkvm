use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, EvalAtRow, RelationEntry, ORIGINAL_TRACE_IDX,
};

use crate::components::lookups::{
    KeccakBitNotAndLookupElements, KeccakBitRotateLookupElements, KeccakStateLookupElements,
    KeccakXorLookupElements,
};

use super::constants::{LANE_SIZE, ROTATIONS};

pub struct KeccakRoundEval<'a, E> {
    pub(crate) index: usize,
    pub(crate) eval: E,
    pub(crate) state_lookup_elements: &'a KeccakStateLookupElements,
    pub(crate) xor_lookup_elements: &'a KeccakXorLookupElements,
    pub(crate) bit_not_and_lookup_elements: &'a KeccakBitNotAndLookupElements,
    pub(crate) bit_rotate_lookup_elements: &'a KeccakBitRotateLookupElements,
}

impl<E: EvalAtRow> KeccakRoundEval<'_, E> {
    pub fn eval(mut self) -> E {
        let mut a = Vec::from_iter(std::iter::repeat_with(|| self.next_u64()).take(25));
        let input_state = Self::state_to_lookup_values(&a);

        // θ step
        // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
        // D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
        // A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
        let mut c = Vec::new();
        for x in 0..5 {
            let mut xor = a[x].clone();

            for i in 1..5 {
                xor = self.xor(&xor, &a[x + i * 5]);
            }
            c.push(xor);
        }

        let mut d = Vec::new();
        for x in 0..5 {
            let rot_c = self.rotate_left(&c[(x + 1) % 5], 1);
            let xor = self.xor(&c[(x + 4) % 5], &rot_c);
            d.push(xor);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + y * 5] = self.xor(&a[x + y * 5], &d[x]);
            }
        }

        // ρ and π steps
        // B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)
        let zero = std::array::from_fn(|_idx| E::F::zero());
        let mut b = vec![zero; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + ((2 * x + 3 * y) % 5) * 5] =
                    self.rotate_left(&a[x + y * 5], ROTATIONS[x + y * 5]);
            }
        }

        // χ step
        // A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
        for x in 0..5 {
            for y in 0..5 {
                let rhs = self.bitwise_not_and(&b[(x + 1) % 5 + y * 5], &b[(x + 2) % 5 + y * 5]);
                a[x + y * 5] = self.xor(&b[x + y * 5], &rhs);
            }
        }

        // ι step
        // A[0,0] = A[0,0] xor RC
        let rc = std::array::from_fn(|i| {
            self.eval.get_preprocessed_column(PreProcessedColumnId {
                id: format!("keccak_{index}_round_constant_{i}", index = self.index),
            })
        });
        a[0] = self.xor(&a[0], &rc);

        let is_padding = {
            // is_padding is the last column in the component trace.
            let [is_padding, _next_is_padding] =
                self.eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
            let _next_is_first = self.eval.get_preprocessed_column(PreProcessedColumnId {
                id: format!("keccak_{index}_is_last_row", index = self.index),
            });
            // constraint padding column to be either 0 or 1, and enforce that it only goes from 1 to 0 on last row.
            self.eval
                .add_constraint(is_padding.clone() * (E::F::one() - is_padding.clone()));
            // TODO: enforcing this constraint requires bit reversing the trace
            //
            // self.eval.add_constraint(
            //     (E::F::one() - next_is_first.clone())
            //         * is_padding.clone()
            //         * (E::F::one() - next_is_padding.clone()),
            // );
            is_padding
        };

        let output_state = Self::state_to_lookup_values(&a);

        self.eval.add_to_relation(RelationEntry::new(
            self.state_lookup_elements,
            (is_padding.clone() - E::F::one()).into(),
            &input_state,
        ));
        self.eval.add_to_relation(RelationEntry::new(
            self.state_lookup_elements,
            (E::F::one() - is_padding).into(),
            &output_state,
        ));

        self.eval.finalize_logup_in_pairs();
        self.eval
    }

    fn state_to_lookup_values(state: &[[E::F; LANE_SIZE]]) -> Vec<E::F> {
        state.iter().flatten().cloned().collect()
    }

    fn next_u64(&mut self) -> [E::F; LANE_SIZE] {
        std::array::from_fn(|_idx| self.eval.next_trace_mask())
    }

    fn xor(&mut self, a: &[E::F; LANE_SIZE], b: &[E::F; LANE_SIZE]) -> [E::F; LANE_SIZE] {
        let xor = self.next_u64();

        for i in 0..LANE_SIZE {
            self.eval.add_to_relation(RelationEntry::new(
                self.xor_lookup_elements,
                E::EF::one(),
                &[a[i].clone(), b[i].clone(), xor[i].clone()],
            ));
        }
        xor
    }

    fn bitwise_not_and(
        &mut self,
        a: &[E::F; LANE_SIZE],
        b: &[E::F; LANE_SIZE],
    ) -> [E::F; LANE_SIZE] {
        let res = self.next_u64();

        for i in 0..LANE_SIZE {
            self.eval.add_to_relation(RelationEntry::new(
                self.bit_not_and_lookup_elements,
                E::EF::one(),
                &[a[i].clone(), b[i].clone(), res[i].clone()],
            ));
        }
        res
    }

    fn rotate_left(&mut self, a: &[E::F; LANE_SIZE], r: usize) -> [E::F; LANE_SIZE] {
        if r == 0 {
            return a.clone();
        }

        let bit_rotate = r % 8;
        let limb_rotate = (r / 8) as i8;

        let bits_low = self.next_u64();
        let bits_high = self.next_u64();
        let out_lane = self.next_u64();

        for i in 0i8..8 {
            self.eval.add_to_relation(RelationEntry::new(
                self.bit_rotate_lookup_elements,
                E::EF::one(),
                &[
                    a[i as usize].clone(),
                    E::F::from(BaseField::from(bit_rotate as u32)),
                    bits_high[i as usize].clone(),
                    bits_low[i as usize].clone(),
                ],
            ));

            // x % 2^n = x & (2^n - 1)
            let low = (i - limb_rotate) & 0b111;
            let high = (i - limb_rotate + 7) & 0b111;

            self.eval.add_constraint(
                bits_low[low as usize].clone() + bits_high[high as usize].clone()
                    - out_lane[i as usize].clone(),
            );
        }

        out_lane
    }
}
