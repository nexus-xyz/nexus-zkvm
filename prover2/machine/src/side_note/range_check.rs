use std::{collections::BTreeMap, ops::Deref};

use stwo_prover::core::fields::m31;

#[derive(Debug, Default, Clone)]
pub struct RangeCheckMultiplicities<const N: u32> {
    multiplicities: BTreeMap<u8, u32>,
}

impl<const N: u32> RangeCheckMultiplicities<N> {
    pub fn add_value(&mut self, value: u8) {
        assert!(u32::from(value) < N);
        let mult = self.multiplicities.entry(value).or_default();

        assert!(*mult < m31::P - 1);
        *mult += 1;
    }

    pub fn add_values_from_slice(&mut self, values: &[u8]) {
        for &value in values {
            self.add_value(value);
        }
    }

    pub fn append(&mut self, mults: Self) {
        for (val, mult) in mults.multiplicities {
            let curr = self.multiplicities.entry(val).or_default();
            assert!(*curr + mult < m31::P);

            *curr += mult;
        }
    }
}

impl<const N: u32> Deref for RangeCheckMultiplicities<N> {
    type Target = BTreeMap<u8, u32>;

    fn deref(&self) -> &Self::Target {
        &self.multiplicities
    }
}

#[derive(Debug, Default, Clone)]
pub struct RangeCheckAccumulator {
    pub range8: RangeCheckMultiplicities<8>,
    pub range16: RangeCheckMultiplicities<16>,
    pub range32: RangeCheckMultiplicities<32>,
    pub range64: RangeCheckMultiplicities<64>,
    pub range128: RangeCheckMultiplicities<128>,
    pub range256: RangeCheckMultiplicities<256>,
}

impl RangeCheckAccumulator {
    pub fn append(&mut self, accum: Self) {
        let Self {
            range8,
            range16,
            range32,
            range64,
            range128,
            range256,
        } = accum;

        self.range8.append(range8);
        self.range16.append(range16);
        self.range32.append(range32);
        self.range64.append(range64);
        self.range128.append(range128);
        self.range256.append(range256);
    }
}
