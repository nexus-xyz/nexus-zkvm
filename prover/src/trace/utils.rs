use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo_prover::core::{
    backend::simd::column::BaseColumn,
    fields::{m31::BaseField, Field},
};

use nexus_vm::WORD_SIZE;

pub use stwo_prover::core::utils::bit_reverse;

use super::program::{Word, WordWithEffectiveBits};

/// Trait for BaseField representation
pub(crate) trait IntoBaseFields<const N: usize> {
    fn into_base_fields(self) -> [BaseField; N];
}

impl IntoBaseFields<1> for bool {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl IntoBaseFields<1> for u8 {
    fn into_base_fields(self) -> [BaseField; 1] {
        [BaseField::from(self as u32)]
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for [bool; WORD_SIZE] {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for Word {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        std::array::from_fn(|i| BaseField::from(self[i] as u32))
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for WordWithEffectiveBits {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        self.0.into_base_fields()
    }
}

impl IntoBaseFields<{ WORD_SIZE }> for u32 {
    fn into_base_fields(self) -> [BaseField; WORD_SIZE] {
        let bytes = self.to_le_bytes();
        std::array::from_fn(|i| BaseField::from(bytes[i] as u32))
    }
}

/// Trait for reading Basefields
pub(crate) trait FromBaseFields<const N: usize> {
    fn from_base_fields(elms: [BaseField; N]) -> Self;
}

impl FromBaseFields<WORD_SIZE> for Word {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let mut ret = Word::default();
        for (i, b) in elms.iter().enumerate() {
            let read = b.0;
            assert!(read < 256, "invalid byte value");
            ret[i] = read as u8;
        }
        ret
    }
}

impl FromBaseFields<WORD_SIZE> for u32 {
    fn from_base_fields(elms: [BaseField; WORD_SIZE]) -> Self {
        let bytes = Word::from_base_fields(elms);
        u32::from_le_bytes(bytes)
    }
}

// TODO: patch upstream to make it public and remove / or use pub methods from tests.
pub fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
    let mut ret = Vec::with_capacity(values.len());
    let n = values.len();
    let half_len = n / 2;

    (0..half_len)
        .into_par_iter()
        .map(|i| values[i << 1])
        .chain(
            (0..half_len)
                .into_par_iter()
                .map(|i| values[n - 1 - (i << 1)]),
        )
        .collect_into_vec(&mut ret);
    ret
}

pub fn finalize_columns(columns: Vec<Vec<BaseField>>) -> Vec<BaseColumn> {
    let mut ret = Vec::with_capacity(columns.len());
    columns
        .into_par_iter()
        .map(|col| {
            let mut eval = coset_order_to_circle_domain_order(col.as_slice());
            bit_reverse(&mut eval);
            BaseColumn::from_iter(eval)
        })
        .collect_into_vec(&mut ret);
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_prover::core::{
        fields::m31::M31,
        utils::{bit_reverse, bit_reverse_index, coset_index_to_circle_domain_index},
    };

    #[test]
    fn test_order() {
        let log_size = 3;
        let vals: Vec<M31> = (0..1 << log_size).map(M31::from).collect();
        let mut reordered = coset_order_to_circle_domain_order(&vals);
        bit_reverse(&mut reordered);

        for (i, reordered) in reordered.iter().enumerate().take(1 << log_size) {
            let idx = bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
            assert_eq!(reordered, &vals[idx]);
        }
    }
}
