use std::simd::u32x16;

use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, Relation},
    core::{
        backend::{
            simd::{
                column::BaseColumn,
                m31::{PackedBaseField, LOG_N_LANES},
                qm31::PackedSecureField,
                SimdBackend,
            },
            Column,
        },
        fields::{m31::BaseField, qm31::SecureField},
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::extensions::ComponentTrace;

use super::{preprocessed_columns::BitwiseTable, BitwiseOp};

/// Accumulator that keeps track of the number of times each input has been used.
#[derive(Debug, Clone)]
pub struct BitwiseAccumulator<const ELEM_BITS: u32, const EXPAND_BITS: u32> {
    /// 2^(2*EXPAND_BITS) multiplicity columns. Index (al, bl) of column (ah, bh) is the
    /// number of times ah||al op bh||bl has been used.
    pub mults: Vec<BaseColumn>,
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32> Default
    for BitwiseAccumulator<ELEM_BITS, EXPAND_BITS>
{
    fn default() -> Self {
        Self {
            mults: (0..(1 << (2 * EXPAND_BITS)))
                .map(|_| {
                    BaseColumn::zeros(
                        1 << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits(),
                    )
                })
                .collect(),
        }
    }
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32> BitwiseAccumulator<ELEM_BITS, EXPAND_BITS> {
    pub fn add_input(&mut self, a: u32x16, b: u32x16) {
        // Split a and b into high and low parts, according to ELEMENT_BITS and EXPAND_BITS.
        // The high part is the index of the multiplicity column.
        // The low part is the index of the element in that column.
        let al =
            a & u32x16::splat((1 << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits()) - 1);
        let ah = a >> BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();
        let bl =
            b & u32x16::splat((1 << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits()) - 1);
        let bh = b >> BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();
        let column_idx = (ah << EXPAND_BITS) + bh;
        let offset = (al << BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits()) + bl;

        // Since the indices may collide, we cannot use scatter simd operations here.
        // Instead, loop over packed values.
        for (column_idx, offset) in column_idx.as_array().iter().zip(offset.as_array().iter()) {
            self.mults[*column_idx as usize].as_mut_slice()[*offset as usize].0 += 1;
        }
    }
}

/// Generates the interaction trace for the bitwise table.
/// Returns the interaction trace, the Preprocessed trace, and the claimed sum.
#[allow(clippy::type_complexity)]
pub(super) fn generate_interaction_trace<
    const ELEM_BITS: u32,
    const EXPAND_BITS: u32,
    X: Relation<PackedBaseField, PackedSecureField>,
    B: BitwiseOp,
>(
    component_trace: ComponentTrace,
    lookup_elements: &X,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let limb_bits = BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

    let offsets_vec = u32x16::from_array(std::array::from_fn(|i| i as u32));
    let mut logup_gen =
        LogupTraceGenerator::new(BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits());

    // Iterate each pair of columns, to batch their lookup together.
    // There are 2^(2*EXPAND_BITS) column, for each combination of ah, bh.
    let mults = &component_trace.original_trace;
    let mut iter = mults.iter().enumerate().array_chunks::<2>();
    for [(i0, mults0), (i1, mults1)] in &mut iter {
        let mut col_gen = logup_gen.new_col();

        // Extract ah, bh from column index.
        let ah0 = i0 as u32 >> EXPAND_BITS;
        let bh0 = i0 as u32 & ((1 << EXPAND_BITS) - 1);
        let ah1 = i1 as u32 >> EXPAND_BITS;
        let bh1 = i1 as u32 & ((1 << EXPAND_BITS) - 1);

        // Each column has 2^(2*LIMB_BITS) rows, packed in N_LANES.
        #[allow(clippy::needless_range_loop)]
        for vec_row in
            0..(1 << (BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() - LOG_N_LANES))
        {
            // vec_row is LIMB_BITS of al and LIMB_BITS - LOG_N_LANES of bl.
            // Extract al, blh from vec_row.
            let al = vec_row >> (limb_bits - LOG_N_LANES);
            let blh = vec_row & ((1 << (limb_bits - LOG_N_LANES)) - 1);

            // Construct the 3 vectors a, b, c.
            let a0 = u32x16::splat((ah0 << limb_bits) | al);
            let a1 = u32x16::splat((ah1 << limb_bits) | al);
            // bll is just the consecutive numbers 0 .. N_LANES-1.
            let b0 = u32x16::splat((bh0 << limb_bits) | (blh << LOG_N_LANES)) | offsets_vec;
            let b1 = u32x16::splat((bh1 << limb_bits) | (blh << LOG_N_LANES)) | offsets_vec;

            let c0 = B::call_simd(a0, b0);
            let c1 = B::call_simd(a1, b1);

            let p0: PackedSecureField = lookup_elements
                .combine(&[a0, b0, c0].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }));
            let p1: PackedSecureField = lookup_elements
                .combine(&[a1, b1, c1].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }));

            let num = p1 * mults0.data[vec_row as usize] + p0 * mults1.data[vec_row as usize];
            let denom = p0 * p1;
            col_gen.write_frac(vec_row as usize, -num, denom);
        }
        col_gen.finalize_col();
    }

    // If there is an odd number of lookup expressions, handle the last one.
    if let Some(rem) = iter.into_remainder() {
        if let Some((i, mults)) = rem.collect::<Vec<_>>().pop() {
            let mut col_gen = logup_gen.new_col();
            let ah = i as u32 >> EXPAND_BITS;
            let bh = i as u32 & ((1 << EXPAND_BITS) - 1);

            #[allow(clippy::needless_range_loop)]
            for vec_row in
                0..(1 << (BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() - LOG_N_LANES))
            {
                // vec_row is LIMB_BITS of a, and LIMB_BITS - LOG_N_LANES of b.
                let al = vec_row >> (limb_bits - LOG_N_LANES);
                let a = u32x16::splat((ah << limb_bits) | al);
                let bm = vec_row & ((1 << (limb_bits - LOG_N_LANES)) - 1);
                let b = u32x16::splat((bh << limb_bits) | (bm << LOG_N_LANES)) | offsets_vec;

                let c = B::call_simd(a, b);

                let p: PackedSecureField = lookup_elements.combine(
                    &[a, b, c].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }),
                );

                let num = mults.data[vec_row as usize];
                let denom = p;
                col_gen.write_frac(vec_row as usize, PackedSecureField::from(-num), denom);
            }
            col_gen.finalize_col();
        }
    }

    logup_gen.finalize_last()
}
