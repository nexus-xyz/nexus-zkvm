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
    collections::HashMap,
    ops::{Mul, Sub},
};

use itertools::zip_eq;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{
        backend::simd::{column::BaseColumn, SimdBackend},
        channel::Channel,
        fields::{m31::BaseField, qm31::SecureField, secure_column::SecureColumnByCoords, Field},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        utils::bit_reverse,
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

pub fn generate_trace<L, F, A>(
    log_sizes: L,
    execution: F,
    args: A,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
where
    L: IntoIterator<Item = u32>,
    F: FnOnce(&mut [&mut [BaseField]], A),
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

    execution(cols.as_mut_slice(), args);

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
pub fn generate_secure_field_trace<L, F, A>(
    log_sizes: L, // each element is the height of a SecureField column = four BaseField columns
    execution: F,
    args: A,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
where
    L: IntoIterator<Item = u32>,
    F: FnOnce(&mut [&mut [SecureField]], A),
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

    execution(cols.as_mut_slice(), args);

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

// Give names to columns, example usage in addition.rs
#[derive(Clone, Debug)]
pub struct ColumnNameMap<T> {
    next: usize,
    map: HashMap<T, std::ops::Range<usize>>,
    ranges: Vec<(T, std::ops::Range<usize>)>,
    finalized: bool,
}
impl<T: Eq + PartialEq + std::hash::Hash> ColumnNameMap<T> {
    pub fn new() -> Self {
        Self {
            next: 0,
            map: HashMap::new(),
            ranges: Vec::new(),
            finalized: false,
        }
    }
    pub fn allocate(mut self, name: &T, size: usize) -> Self
    where
        T: Clone,
    {
        assert!(!self.finalized);
        let range = self.next..self.next + size;
        self.next += size;
        let overwritten = self.map.insert(name.clone(), range.clone());
        debug_assert!(overwritten.is_none());
        self.ranges.push((name.clone(), range));
        self
    }
    pub fn allocate_bulk<I>(mut self, bulk: I) -> Self
    where
        I: IntoIterator<Item = (T, usize)>,
        T: Clone,
    {
        assert!(!self.finalized);
        for (name, size) in bulk {
            self = self.allocate(&name, size);
        }
        self
    }
    pub fn finalize(mut self) -> Self {
        self.finalized = true;
        self
    }
    pub fn num_columns(&self) -> usize {
        assert!(self.finalized);
        self.next
    }
    pub fn get(&self, name: &T) -> &std::ops::Range<usize> {
        assert!(self.finalized);
        self.map.get(name).unwrap()
    }
    pub fn nth_col(&self, name: &T, i: usize) -> usize {
        assert!(self.finalized);
        assert!(i < self.get(name).end - self.get(name).start);
        self.get(name).start + i
    }
    pub fn ranges(&self) -> &[(T, std::ops::Range<usize>)] {
        assert!(self.finalized);
        &self.ranges
    }
}
impl<T: Eq + PartialEq + std::hash::Hash> Default for ColumnNameMap<T> {
    fn default() -> Self {
        Self::new()
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
    fn lookup_trace_masks<T: Clone + Eq + std::hash::Hash>(
        &mut self,
        names: &ColumnNameMap<T>,
    ) -> HashMap<T, Vec<Self::F>> {
        let [masks] = self.lookup_trace_masks_with_offsets(names, 0, [0]);
        masks
    }
    fn lookup_trace_masks_with_offsets<
        T: Clone + Eq + PartialEq + std::hash::Hash,
        const N: usize,
    >(
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
        let alpha_powers = std::array::from_fn(|_| {
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
