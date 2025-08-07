// Copyright 2024 StarkWare Industries Ltd.
// Copyright 2024-2025 Nexus Laboratories, Ltd.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

// The code below was copied from
// https://github.com/starkware-libs/stwo/blob/f7871979e6ea8e606dc4674301b7d8b28b5838ed/crates/prover/src/core/utils.rs#L108
// and since then modified.

use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo::core::fields::Field;

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
