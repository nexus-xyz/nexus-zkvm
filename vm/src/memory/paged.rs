use std::collections::BTreeMap;

use ark_ff::AdditiveGroup;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::cacheline::CacheLine;
use super::{Memory, MemoryProof};
use crate::circuit::F;
use crate::error::Result;

/// A simple memory without memory proofs.
///
/// The `Paged` memory is organized as a collection of 4K pages.
/// Each page holds 128 `CacheLines`; a binary tree is used to
/// represent a sparsely populated memory space.
#[derive(Default)]
pub struct Paged {
    tree: BTreeMap<u32, Page>,
}
type Page = [CacheLine; 128];

/// A minimal `MemoryProof` implementation that doesn't provide
/// in-circuit verification.
#[derive(Default, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct UncheckedMemory {
    pub data: [F; 2],
}

impl MemoryProof for UncheckedMemory {
    type Params = ();

    fn params(_cs: ConstraintSystemRef<F>) -> Result<Self::Params, SynthesisError> {
        Ok(())
    }

    fn circuit(
        &self,
        _cs: ConstraintSystemRef<F>,
        _params: &Self::Params,
        _root: &FpVar<F>,
        _data: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn commit(&self) -> F {
        F::ZERO
    }

    fn data(&self) -> [F; 2] {
        self.data
    }
}

impl Memory for Paged {
    type Proof = UncheckedMemory;

    fn query(&self, addr: u32) -> (&CacheLine, Self::Proof) {
        let page = addr >> 12;
        let offset = ((addr >> 5) & 0x7f) as usize;

        const ZERO: CacheLine = CacheLine { dwords: [0; 4] };
        let cl = match self.tree.get(&page) {
            None => &ZERO,
            Some(arr) => &arr[offset],
        };
        (cl, UncheckedMemory { data: cl.scalars() })
    }

    fn update<F>(&mut self, addr: u32, f: F) -> Result<Self::Proof>
    where
        F: Fn(&mut CacheLine) -> Result<()>,
    {
        let page = addr >> 12;
        let offset = ((addr >> 5) & 0x7f) as usize;
        let arr = self
            .tree
            .entry(page)
            .or_insert_with(|| [CacheLine::default(); 128]);
        f(&mut arr[offset])?;
        Ok(UncheckedMemory { data: arr[offset].scalars() })
    }
}
