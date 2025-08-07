use nexus_common::constants::WORD_SIZE_HALVED;
use num_traits::One;
use stwo_constraint_framework::{
    preprocessed_columns::PreProcessedColumnId, EvalAtRow, RelationEntry, ORIGINAL_TRACE_IDX,
};

use crate::components::lookups::{KeccakStateLookupElements, LoadStoreLookupElements};

pub struct PermutationMemoryCheckEval<'a, E> {
    pub(crate) eval: E,
    pub(crate) state_lookup_elements: &'a KeccakStateLookupElements,
    pub(crate) memory_lookup_elements: &'a LoadStoreLookupElements,
}

impl<E: EvalAtRow> PermutationMemoryCheckEval<'_, E> {
    const STATE_SIZE: usize = super::PermutationMemoryCheckEval::STATE_SIZE;

    pub fn eval(mut self) -> E {
        let input_state = self.next_state();
        let output_state = self.next_state();
        let addrs = self.next_state_addresses();
        let prev_ts = self.next_state_timestamps();
        let next_ts = self.next_state_timestamps();
        let addr_carries = self.next_state();
        let ts_carries = self.next_state();

        let is_padding = {
            // is_padding is the last column in the component trace.
            let [is_padding, _next_is_padding] =
                self.eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
            let _next_is_first = self.eval.get_preprocessed_column(PreProcessedColumnId {
                id: "keccak_memory_check_is_last_row".to_string(),
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

        self.eval.add_to_relation(RelationEntry::new(
            self.state_lookup_elements,
            (E::F::one() - is_padding.clone()).into(),
            &input_state,
        ));
        self.eval.add_to_relation(RelationEntry::new(
            self.state_lookup_elements,
            (is_padding.clone() - E::F::one()).into(),
            &output_state,
        ));

        for i in 0..Self::STATE_SIZE {
            let prev_val = &input_state[i];
            let next_val = &output_state[i];
            let j = i * WORD_SIZE_HALVED;
            // (addr, val, ts)
            let sub_access = [
                &addrs[j..j + WORD_SIZE_HALVED],
                std::slice::from_ref(prev_val),
                &prev_ts[j..j + WORD_SIZE_HALVED],
            ]
            .concat();
            let add_access = [
                &addrs[j..j + WORD_SIZE_HALVED],
                std::slice::from_ref(next_val),
                &next_ts[j..j + WORD_SIZE_HALVED],
            ]
            .concat();

            self.eval.add_to_relation(RelationEntry::new(
                self.memory_lookup_elements,
                (is_padding.clone() - E::F::one()).into(),
                &sub_access,
            ));
            self.eval.add_to_relation(RelationEntry::new(
                self.memory_lookup_elements,
                (E::F::one() - is_padding.clone()).into(),
                &add_access,
            ));
        }

        for i in (0..Self::STATE_SIZE).step_by(WORD_SIZE_HALVED) {
            let addr = &addrs[i..i + WORD_SIZE_HALVED];
            let Some(next_addr) = addrs.get(i + WORD_SIZE_HALVED..i + WORD_SIZE_HALVED * 2) else {
                break;
            };
            let carry = addr_carries[i / WORD_SIZE_HALVED].clone();

            self.eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (next_addr[0].clone() + carry.clone() * E::F::from((1 << 16).into())
                        - addr[0].clone()
                        - E::F::one()),
            );
            self.eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (next_addr[1].clone() - addr[1].clone() - carry.clone()),
            );
        }

        for (i, (prev_ts, next_ts)) in prev_ts
            .chunks_exact(WORD_SIZE_HALVED)
            .zip(next_ts.chunks_exact(WORD_SIZE_HALVED))
            .enumerate()
        {
            let carry = ts_carries[i].clone();
            self.eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (next_ts[0].clone() + carry.clone() * E::F::from((1 << 16).into())
                        - prev_ts[0].clone()
                        - E::F::one()),
            );
            self.eval.add_constraint(
                (E::F::one() - is_padding.clone())
                    * (next_ts[1].clone() - prev_ts[1].clone() - carry.clone()),
            );
        }

        self.eval.finalize_logup_in_pairs();

        self.eval
    }

    fn next_state_with_size(&mut self, size: usize) -> Vec<E::F> {
        std::iter::repeat_with(|| self.eval.next_trace_mask())
            .take(size)
            .collect()
    }

    fn next_state(&mut self) -> Vec<E::F> {
        self.next_state_with_size(Self::STATE_SIZE)
    }

    fn next_state_addresses(&mut self) -> Vec<E::F> {
        self.next_state_with_size(Self::STATE_SIZE * WORD_SIZE_HALVED)
    }

    fn next_state_timestamps(&mut self) -> Vec<E::F> {
        self.next_state_with_size(Self::STATE_SIZE * WORD_SIZE_HALVED)
    }
}
