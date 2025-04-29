use crate::extensions::keccak::{
    bit_rotate::BitRotateAccumulator, bitwise_table::BitwiseAccumulator,
};

#[derive(Debug, Copy, Clone)]
pub enum BitOp {
    /// a ^ b
    Xor,
    /// !a & b
    BitNotAnd,
    /// a.rotate_left(r)
    Rotation(u32),
}

#[derive(Default)]
pub struct KeccakSideNote {
    pub(crate) inputs: Vec<[u64; 25]>,
    pub(crate) timestamps: Vec<Vec<u32>>,
    pub(crate) addresses: Vec<u32>,
    pub(crate) xor_accum: Option<BitwiseAccumulator>,
    pub(crate) bit_not_and_accum: Option<BitwiseAccumulator>,
    pub(crate) bit_rotate_accum: BitRotateAccumulator,
    // interaction trace hint for each rounds split component
    pub(crate) round_lookups: Vec<RoundLookups>,
}

#[derive(Default)]
pub struct RoundLookups {
    pub(crate) bitwise_lookups: Vec<([usize; 3], BitOp)>,
    pub(crate) xor_rc_lookup: (usize, usize),
    pub(crate) output_state_lookup: Vec<usize>,
}
