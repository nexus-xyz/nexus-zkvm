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
// https://github.com/starkware-libs/stwo/tree/39882cca6af9d2666b0e287ba3550045eac76d4a/crates/prover/src/examples/blake/xor_table
// and since then modified.

//! Bitwise table component. Generic on `ELEM_BITS` and `EXPAND_BITS`.
//!
//! The table has all triplets of (a, b, a^b, !a&b), where a, b are in the range [0,2^ELEM_BITS).
//! a,b are split into high and low parts, of size `EXPAND_BITS` and `ELEM_BITS - EXPAND_BITS`
//! respectively.
//!
//! The component itself will hold 2^(2*EXPAND_BITS) multiplicity columns, each of size
//! 2^(ELEM_BITS - EXPAND_BITS).
//!
//! The constant columns correspond only to the smaller table of the lower `ELEM_BITS - EXPAND_BITS`
//! bitwise ops: (a_l, b_l, a_l^b_l, !a_l&b_l).
//! The rest of the lookups are computed based on these constant columns.

use std::{marker::PhantomData, simd::u32x16};

use stwo_prover::{
    constraint_framework::{EvalAtRow, FrameworkEval},
    core::{
        backend::simd::SimdBackend,
        fields::{m31::BaseField, qm31::SecureField},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use crate::{
    components::{
        lookups::{KeccakBitNotAndLookupElements, KeccakXorLookupElements},
        AllLookupElements, RegisteredLookupBound,
    },
    extensions::{BuiltInExtension, ComponentTrace, FrameworkEvalExt},
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

pub(crate) mod constraints;
pub(crate) mod preprocessed_columns;
pub(crate) mod trace;

pub const ELEM_BITS: u32 = 8;
pub const EXPAND_BITS: u32 = 2;

pub type BitwiseAccumulator = trace::BitwiseAccumulator<ELEM_BITS, EXPAND_BITS>;

pub trait BitwiseOp: Send + Sync + 'static {
    const PREPROCESSED_TRACE_GEN: bool;
    const C_COL_INDEX: usize;
    fn call(a: u32, b: u32) -> u32;
    fn call_simd(a: u32x16, b: u32x16) -> u32x16;
    fn accum_mut(side_note: &mut SideNote) -> &mut BitwiseAccumulator;
}

#[derive(Debug, Clone)]
pub struct BitwiseTable<const ELEM_BITS: u32, const EXPAND_BITS: u32, R, B> {
    pub(crate) _phantom: PhantomData<(B, R)>,
}

// auto-derive enforces bounds on generic parameters

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R, B> PartialEq
    for BitwiseTable<ELEM_BITS, EXPAND_BITS, R, B>
{
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R, B> Eq
    for BitwiseTable<ELEM_BITS, EXPAND_BITS, R, B>
{
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R, B> std::hash::Hash
    for BitwiseTable<ELEM_BITS, EXPAND_BITS, R, B>
{
    fn hash<H: std::hash::Hasher>(&self, _state: &mut H) {}
}

pub struct BitwiseTableEval<const ELEM_BITS: u32, const EXPAND_BITS: u32, R, B> {
    pub lookup_elements: R,
    _phantom_data: PhantomData<B>,
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R: RegisteredLookupBound, B: BitwiseOp>
    BitwiseTableEval<ELEM_BITS, EXPAND_BITS, R, B>
{
    const LOG_SIZE: u32 = 12;
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R: RegisteredLookupBound, B: BitwiseOp>
    FrameworkEval for BitwiseTableEval<ELEM_BITS, EXPAND_BITS, R, B>
{
    fn log_size(&self) -> u32 {
        preprocessed_columns::BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        preprocessed_columns::BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        let eval = constraints::BitwiseTableEvalAtRow::<'_, ELEM_BITS, EXPAND_BITS, E, R, B> {
            eval,
            lookup_elements: &self.lookup_elements,
            _phantom_data: Default::default(),
        };
        eval.eval()
    }
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R: RegisteredLookupBound, B: BitwiseOp>
    FrameworkEvalExt for BitwiseTableEval<ELEM_BITS, EXPAND_BITS, R, B>
{
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        let lookup: &R = lookup_elements.as_ref();
        Self {
            lookup_elements: lookup.clone(),
            _phantom_data: Default::default(),
        }
    }
    fn dummy(log_size: u32) -> Self {
        assert_eq!(log_size, Self::LOG_SIZE);
        Self {
            lookup_elements: R::dummy(),
            _phantom_data: Default::default(),
        }
    }
}

impl<const ELEM_BITS: u32, const EXPAND_BITS: u32, R: RegisteredLookupBound, B: BitwiseOp>
    BuiltInExtension for BitwiseTable<ELEM_BITS, EXPAND_BITS, R, B>
{
    type Eval = BitwiseTableEval<ELEM_BITS, EXPAND_BITS, R, B>;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _program_trace_ref: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        if B::PREPROCESSED_TRACE_GEN {
            let table = preprocessed_columns::BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0);
            let preprocessed = table.generate_constant_trace();
            preprocessed
                .into_iter()
                .map(|x| {
                    CircleEvaluation::new(CanonicCoset::new(table.column_bits()).circle_domain(), x)
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    fn generate_component_trace(
        &self,
        _log_size: u32,
        _program_trace_ref: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace {
        let preprocessed = if B::PREPROCESSED_TRACE_GEN {
            preprocessed_columns::BitwiseTable::new(ELEM_BITS, EXPAND_BITS, 0)
                .generate_constant_trace()
        } else {
            vec![]
        };
        let accum_mut = B::accum_mut(side_note);
        let mults = std::mem::take(&mut accum_mut.mults);

        ComponentTrace {
            log_size: Self::Eval::LOG_SIZE,
            preprocessed_trace: preprocessed,
            original_trace: mults,
        }
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let lookup_elements: &R = lookup_elements.as_ref();
        trace::generate_interaction_trace::<ELEM_BITS, EXPAND_BITS, _, B>(
            component_trace,
            <R as RegisteredLookupBound>::as_relation_ref(lookup_elements),
        )
    }

    fn compute_log_size(&self, _side_note: &SideNote) -> u32 {
        Self::Eval::LOG_SIZE
    }

    fn preprocessed_trace_sizes(_log_size: u32) -> Vec<u32> {
        if B::PREPROCESSED_TRACE_GEN {
            std::iter::repeat(Self::Eval::LOG_SIZE).take(4).collect()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone)]
pub struct Xor;
impl BitwiseOp for Xor {
    const PREPROCESSED_TRACE_GEN: bool = true;
    const C_COL_INDEX: usize = 2;

    fn call(a: u32, b: u32) -> u32 {
        a ^ b
    }

    fn call_simd(a: u32x16, b: u32x16) -> u32x16 {
        a ^ b
    }

    fn accum_mut(side_note: &mut SideNote) -> &mut BitwiseAccumulator {
        side_note
            .keccak
            .xor_accum
            .as_mut()
            .expect("keccak side note is empty")
    }
}

#[derive(Debug, Clone)]
pub struct BitNotAnd;
impl BitwiseOp for BitNotAnd {
    const PREPROCESSED_TRACE_GEN: bool = false;
    const C_COL_INDEX: usize = 3;

    fn call(a: u32, b: u32) -> u32 {
        !a & b
    }

    fn call_simd(a: u32x16, b: u32x16) -> u32x16 {
        !a & b
    }

    fn accum_mut(side_note: &mut SideNote) -> &mut BitwiseAccumulator {
        side_note
            .keccak
            .bit_not_and_accum
            .as_mut()
            .expect("keccak side note is empty")
    }
}

pub type XorTable = BitwiseTable<ELEM_BITS, EXPAND_BITS, KeccakXorLookupElements, Xor>;
pub type BitNotAndTable =
    BitwiseTable<ELEM_BITS, EXPAND_BITS, KeccakBitNotAndLookupElements, BitNotAnd>;
