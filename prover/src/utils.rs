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
    ops::{self},
};

use num_traits::Zero;
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{column::BaseColumn, SimdBackend},
        fields::{m31::BaseField, qm31::SecureField, secure_column::SecureColumnByCoords, Field},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        utils::bit_reverse,
        ColumnVec,
    },
};

fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
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
                for (i, mask) in masks.iter().cloned().enumerate() {
                    values[i].entry(*name).or_insert_with(Vec::new).push(mask);
                }
            }
        }
        values
    }
}
impl<T: EvalAtRow> EvalAtRowExtra for T {}
pub const WORD_SIZE: usize = nexus_vm::WORD_SIZE;
