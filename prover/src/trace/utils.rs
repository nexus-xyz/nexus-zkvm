use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, SimdBackend},
    fields::m31::BaseField,
};

use nexus_vm::WORD_SIZE;

pub use stwo_prover::core::backend::ColumnOps;

use super::{
    program::{Word, WordWithEffectiveBits},
    utils_external::coset_order_to_circle_domain_order,
};

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

impl IntoBaseFields<1> for BaseField {
    fn into_base_fields(self) -> [BaseField; 1] {
        [self]
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

pub fn finalize_columns(columns: Vec<Vec<BaseField>>) -> Vec<BaseColumn> {
    let mut ret = Vec::with_capacity(columns.len());
    columns
        .into_par_iter()
        .map(|col| {
            let eval = coset_order_to_circle_domain_order(col.as_slice());
            let mut base_column = BaseColumn::from_iter(eval);
            <SimdBackend as ColumnOps<BaseField>>::bit_reverse_column(&mut base_column);
            base_column
        })
        .collect_into_vec(&mut ret);
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo_prover::core::{
        fields::m31::M31,
        utils::{bit_reverse_index, coset_index_to_circle_domain_index},
    };

    #[test]
    fn test_order() {
        let log_size = 3;
        let vals: Vec<M31> = (0..1 << log_size).map(M31::from).collect();
        let reordered = coset_order_to_circle_domain_order(&vals);
        let mut col = BaseColumn::from_iter(reordered.clone());
        <SimdBackend as ColumnOps<BaseField>>::bit_reverse_column(&mut col);

        for (i, reordered) in col.as_slice().iter().enumerate().take(1 << log_size) {
            let idx = bit_reverse_index(coset_index_to_circle_domain_index(i, log_size), log_size);
            assert_eq!(reordered, &vals[idx]);
        }
    }
}
