// This file contains some derived work of stwo codebase

// Copyright 2024 StarkWare Industries Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    array,
    collections::{BTreeMap, HashMap},
    hash::Hash,
    iter,
    ops::{self, Mul, Sub},
};

use itertools::zip_eq;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{assert_constraints, EvalAtRow, FrameworkEval},
    core::{
        backend::simd::{column::BaseColumn, SimdBackend},
        channel::{Blake2sChannel, Channel},
        fields::{m31::BaseField, qm31::SecureField, secure_column::SecureColumnByCoords, Field},
        pcs::{CommitmentSchemeProver, PcsConfig},
        poly::{
            circle::{CanonicCoset, CircleEvaluation, PolyOps as _},
            BitReversedOrder,
        },
        utils::bit_reverse,
        vcs::blake2_merkle::Blake2sMerkleChannel,
        ColumnVec,
    },
};

// TODO: remove 'pub' after using generate_trace in the permutation example
pub fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
    let mut circle_domain_order = Vec::with_capacity(values.len());
    let n = values.len();

    let half_len = n / 2;

    for i in 0..half_len {
        circle_domain_order.push(values[i << 1]);
    }

    for i in 0..half_len {
        circle_domain_order.push(values[n - 1 - (i << 1)]);
    }

    circle_domain_order
}

pub fn generate_trace<L, F>(
    log_sizes: L,
    execution: F,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
where
    L: IntoIterator<Item = u32>,
    F: FnOnce(&mut [&mut [BaseField]]),
{
    let (mut columns, domains): (Vec<_>, Vec<_>) = log_sizes
        .into_iter()
        .map(|log_size| {
            let rows = 1 << log_size as usize;
            (
                vec![BaseField::zero(); rows],
                CanonicCoset::new(log_size).circle_domain(),
            )
        })
        .unzip();

    // asserts the user cannot mutate the number of rows
    let mut cols: Vec<_> = columns.iter_mut().map(|c| c.as_mut_slice()).collect();

    execution(cols.as_mut_slice());

    columns
        .into_iter()
        .zip(domains)
        .map(|(col, domain)| {
            let mut col = coset_order_to_circle_domain_order(col.as_slice());

            bit_reverse(&mut col);

            let col = BaseColumn::from_iter(col);

            CircleEvaluation::new(domain, col)
        })
        .collect()
}

// Similar to generate_trace() but with SecureField matrix
// Especially useful for Montgomery batch inversion.
pub fn generate_secure_field_trace<L, F>(
    log_sizes: L, // each element is the height of a SecureField column = four BaseField columns
    execution: F,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
where
    L: IntoIterator<Item = u32>,
    F: FnOnce(&mut [&mut [SecureField]]),
{
    let (mut columns, domains): (Vec<_>, Vec<_>) = log_sizes
        .into_iter()
        .map(|log_size| {
            let rows = 1 << log_size as usize;
            (
                vec![SecureField::zero(); rows],
                CanonicCoset::new(log_size).circle_domain(),
            )
        })
        .unzip();

    // asserts the user cannot mutate the number of rows
    let mut cols: Vec<_> = columns.iter_mut().map(|c| c.as_mut_slice()).collect();

    execution(cols.as_mut_slice());

    columns
        .into_iter()
        .zip(domains)
        .flat_map(|(col, domain)| {
            let mut col = coset_order_to_circle_domain_order(col.as_slice());
            bit_reverse(&mut col);
            let col = SecureColumnByCoords::<SimdBackend>::from_iter(col);
            col.columns.map(|c| CircleEvaluation::new(domain, c))
        })
        .collect()
}

pub trait ColumnNameItem: Copy + Eq + PartialEq + PartialOrd + Ord + Hash {
    type Iter: IntoIterator<Item = Self>;

    fn items() -> Self::Iter;
    fn size(&self) -> usize;
}

/// A map from a column name to a range within the constraint system.
#[derive(Clone, Debug)]
pub struct ColumnNameMap<T> {
    next: usize,
    map: BTreeMap<T, ops::Range<usize>>, // use of btreemap to preserve order
}

impl<T: ColumnNameItem> Default for ColumnNameMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ColumnNameItem> ops::Deref for ColumnNameMap<T> {
    type Target = BTreeMap<T, ops::Range<usize>>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<T: ColumnNameItem> ColumnNameMap<T> {
    /// Creates a new map instance from the provided static type.
    pub fn new() -> Self {
        let mut next = 0;
        let map = T::items()
            .into_iter()
            .map(|col| {
                let size = col.size();
                let range = next..next + size;

                next += size;

                (col, range)
            })
            .collect();

        Self { next, map }
    }

    /// Returns the total number of allocated columns.
    pub const fn total_columns(&self) -> usize {
        self.next
    }

    /// Extracts the nth element as offset of the given column
    ///
    /// # Panics
    ///
    /// Will panic if the column doesn't exist on the map, or if the provided offset is not
    /// within its bounds.
    pub fn nth_col(&self, name: &T, offset: usize) -> usize {
        let range = &self[name];

        assert!(offset < range.end - range.start);

        range.start + offset
    }

    /// Returns an order-sensitive iterator of ranges.
    pub fn ranges(&self) -> impl Iterator<Item = (&T, &ops::Range<usize>)> {
        self.map.iter()
    }

    /// Creates a map of columns to slices.
    ///
    /// Note: `self` is not strictly needed, but it is convenient as it will avoid
    /// redundant type casting.
    pub fn named_slices<V>(mut values: &mut [V]) -> ColumnNameSlices<T, V> {
        let mut map = HashMap::new();

        for col in T::items() {
            let mid = col.size();

            let (a, b) = values.split_at_mut(mid);
            values = b;

            map.insert(col, a);
        }

        ColumnNameSlices { map }
    }
}

pub struct ColumnNameSlices<'a, T: ColumnNameItem, V> {
    map: HashMap<T, &'a mut [V]>,
}

impl<'a, T: ColumnNameItem, V> ops::Index<T> for ColumnNameSlices<'a, T, V> {
    type Output = [V];

    fn index(&self, index: T) -> &Self::Output {
        self.map[&index]
    }
}

impl<'a, T: ColumnNameItem, V> ops::IndexMut<T> for ColumnNameSlices<'a, T, V> {
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        self.map.get_mut(&index).unwrap()
    }
}

// An extension trait for `EvalAtRow` that provides additional methods.
pub trait EvalAtRowExtra: EvalAtRow {
    /// Returns the mask values of offset zero for the next C columns in the interaction zero.
    fn next_trace_masks<const C: usize>(&mut self) -> [Self::F; C] {
        array::from_fn(|_i| self.next_trace_mask())
    }
    /// Returns the mask values of next_extension_trace_masks() repeatedly.
    fn next_extension_interaction_masks_cur_row<const C: usize>(
        &mut self,
        interaction: usize,
    ) -> [Self::EF; C] {
        array::from_fn(|_i| {
            let [ret] = self.next_extension_interaction_mask(interaction, [0]);
            ret
        })
    }
    /// Returns a hashmap containing a looked up value under each variable name
    /// in the given `IndexAllocator`.
    /// Needs to be called before any column is fetched.
    fn lookup_trace_masks<T: ColumnNameItem>(
        &mut self,
        names: &ColumnNameMap<T>,
    ) -> HashMap<T, Vec<Self::F>> {
        let [masks] = self.lookup_trace_masks_with_offsets(names, 0, [0]);
        masks
    }
    fn lookup_trace_masks_with_offsets<T: ColumnNameItem, const N: usize>(
        &mut self,
        names: &ColumnNameMap<T>,
        interaction: usize,
        offsets: [isize; N],
    ) -> [HashMap<T, Vec<Self::F>>; N] {
        let mut values: [HashMap<T, Vec<Self::F>>; N] = array::from_fn(|_| HashMap::new());
        for (name, range) in names.ranges() {
            let size = range.end - range.start;
            for _ in 0..size {
                let masks = self.next_interaction_mask(interaction, offsets);
                for (i, mask) in masks.iter().enumerate() {
                    values[i]
                        .entry(name.clone())
                        .or_insert_with(Vec::new)
                        .push(*mask);
                }
            }
        }
        values
    }
}
impl<T: EvalAtRow> EvalAtRowExtra for T {}

// This is very similar to LookupElement in logup.rs.
// I'm avoiding logup.rs because it's not randomized preprocessed AIR.
// logup.rs puts claimed_sum (which is not a low-degree polynomial) as constant into constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermElements<const N: usize> {
    pub z: SecureField,
    pub alpha: SecureField,
    alpha_powers: [SecureField; N],
}
impl<const N: usize> PermElements<N> {
    pub fn draw(channel: &mut impl Channel) -> Self {
        let [z, alpha] = channel.draw_felts(2).try_into().unwrap();
        let mut cur = SecureField::one();
        let alpha_powers = array::from_fn(|_| {
            let res = cur;
            cur *= alpha;
            res
        });
        Self {
            z,
            alpha,
            alpha_powers,
        }
    }

    // The iterator needs to return [N] elements. Avoiding a slice because no need of
    // contiguous memory.
    pub fn combine<F: Copy, EF, I: IntoIterator<Item = F>>(&self, values: I) -> EF
    where
        EF: Copy + Zero + From<F> + From<SecureField> + Mul<F, Output = EF> + Sub<EF, Output = EF>,
    {
        zip_eq(values, self.alpha_powers).fold(EF::zero(), |acc, (value, power)| {
            acc + EF::from(power) * value
        }) - EF::from(self.z)
    }
}

pub const WORD_SIZE: usize = 4;

pub trait MachineChip<T> {
    // Called on each row during main trace generation
    fn fill_main_trace(
        r1_val: [u8; WORD_SIZE],
        r2_val: [u8; WORD_SIZE],
        rd_val: &mut [u8; WORD_SIZE],
        rd_idx: usize,
        cols: &mut [&mut [BaseField]],
        row_idx: usize,
        col_names: &ColumnNameMap<T>,
    );
    // Called on each row during constraint evaluation
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        cols: &HashMap<T, Vec<<E as EvalAtRow>::F>>,
        eval: &mut E,
    );
}

use impl_trait_for_tuples::impl_for_tuples;
#[impl_for_tuples(1, 12)]
impl<T> MachineChip<T> for Tuple {
    fn fill_main_trace(
        r1_val: [u8; WORD_SIZE],
        r2_val: [u8; WORD_SIZE],
        rd_val: &mut [u8; WORD_SIZE],
        rd_idx: usize,
        cols: &mut [&mut [BaseField]],
        row_idx: usize,
        col_names: &ColumnNameMap<T>,
    ) {
        for_tuples!( #( Tuple::fill_main_trace(r1_val, r2_val, rd_val, rd_idx, cols, row_idx, col_names); )* );
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        cols: &HashMap<T, Vec<<E as EvalAtRow>::F>>,
        eval: &mut E,
    ) {
        for_tuples!( #( Tuple::add_constraints(cols, eval); )* );
    }
}

pub fn write_word<T: ColumnNameItem>(
    val: [u8; WORD_SIZE],
    dst: &T,
    cols: &mut [&mut [BaseField]],
    col_names: &ColumnNameMap<T>,
    row_idx: usize,
) {
    for i in 0..WORD_SIZE {
        cols[col_names.nth_col(dst, i)][row_idx] = BaseField::from(val[i] as u32);
    }
}

pub fn write_u32<T: ColumnNameItem>(
    val: u32,
    dst: &T,
    cols: &mut [&mut [BaseField]],
    col_names: &ColumnNameMap<T>,
    row_idx: usize,
) {
    let val: [u8; WORD_SIZE] = val.to_le_bytes();
    write_word(val, dst, cols, col_names, row_idx);
}

pub trait AssertionCircuit {
    type Columns: ColumnNameItem;

    fn rows_log2() -> u32;
    fn traces(&self) -> Vec<impl FnOnce(&mut [&mut [BaseField]])>;
    fn eval<E: EvalAtRow>(&self, eval: E) -> E;

    fn assert_constraints(&self) {
        let column_names: ColumnNameMap<Self::Columns> = ColumnNameMap::new();
        let num_cols = column_names.total_columns();

        let traces: Vec<_> = self
            .traces()
            .into_iter()
            .map(|trace| {
                generate_trace(iter::repeat(Self::rows_log2()).take(num_cols), |cols| {
                    trace(cols)
                })
            })
            .collect();

        struct Circuit<T: AssertionCircuit> {
            rows_log2: u32,
            t: T,
        }

        impl<T: AssertionCircuit> FrameworkEval for Circuit<T> {
            fn log_size(&self) -> u32 {
                self.rows_log2
            }

            fn max_constraint_log_degree_bound(&self) -> u32 {
                self.log_size() + 1
            }

            fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
                self.t.eval(eval)
            }
        }

        // setup protocol

        let config = PcsConfig::default();
        let coset = CanonicCoset::new(Self::rows_log2() + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset;
        let twiddles = SimdBackend::precompute_twiddles(coset);

        let prover_channel = &mut Blake2sChannel::default();
        let prover_commitment_scheme =
            &mut CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(config, &twiddles);

        // commit traces

        for trace in traces {
            let mut tree_builder = prover_commitment_scheme.tree_builder();
            tree_builder.extend_evals(trace);
            tree_builder.commit(prover_channel);
        }

        // Sanity check

        let traces = prover_commitment_scheme
            .trees
            .as_ref()
            .map(|t| t.polynomials.to_vec());

        assert_constraints(&traces, CanonicCoset::new(Self::rows_log2()), |evaluator| {
            self.eval(evaluator);
        });
    }
}
