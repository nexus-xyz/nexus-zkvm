use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

/// A preprocessed table for the bitwise operation of 2 n_bits numbers.
/// n_expand_bits is an optimization parameter reducing the table's columns' length to
/// 2^(n_bits - n_expand_bits), while storing multiplicities for the n_expand_bits operation.
/// The index_in_table is the column index in the preprocessed table.

#[derive(Debug)]
pub struct BitwiseTable {
    pub n_bits: u32,
    pub n_expand_bits: u32,
    pub index_in_table: usize,
}
impl BitwiseTable {
    pub const fn new(n_bits: u32, n_expand_bits: u32, index_in_table: usize) -> Self {
        Self {
            n_bits,
            n_expand_bits,
            index_in_table,
        }
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!(
                "keccakf_preprocessed_bit_table_{}_{}_{}",
                self.n_bits, self.n_expand_bits, self.index_in_table
            ),
        }
    }

    pub const fn limb_bits(&self) -> u32 {
        self.n_bits - self.n_expand_bits
    }

    pub const fn column_bits(&self) -> u32 {
        2 * self.limb_bits()
    }

    /// Generates the Preprocessed trace for the bitwise-op table.
    pub fn generate_constant_trace(&self) -> Vec<BaseColumn> {
        let limb_bits = self.limb_bits();

        let a_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| BaseField::from_u32_unchecked((i >> limb_bits) as u32))
            .collect();
        let b_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| BaseField::from_u32_unchecked((i & ((1 << limb_bits) - 1)) as u32))
            .collect();
        let c_xor_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| {
                BaseField::from_u32_unchecked(
                    ((i >> limb_bits) ^ (i & ((1 << limb_bits) - 1))) as u32,
                )
            })
            .collect();
        let c_not_and_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| {
                BaseField::from_u32_unchecked(
                    (!(i >> limb_bits) & (i & ((1 << limb_bits) - 1))) as u32,
                )
            })
            .collect();

        vec![a_col, b_col, c_xor_col, c_not_and_col]
    }
}
