use rand::{distributions::Standard, prelude::Distribution, Rng};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::utils::{ColumnNameItem, WORD_SIZE};

#[derive(Clone, Copy, Debug, EnumIter, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum RegisterMachineColumns {
    Clk, // start from 4, increments by 4
    ClkCarryFlag,
    Pc,
    PcCarryFlag,
    IsAdd,
    IsSub,
    IsXor,
    R1Idx,
    R2Idx,
    RdIdx,
    RdIdxNonzero,
    RdIdxNonzeroW,
    RdIdxNonzeroZ,
    R1Val,
    R2Val,
    RdVal,
    RdValWritten, // RdIdxNonZero * RdVal
    R1PrevValue,
    R1PrevTimeStamp,
    R2PrevValue,
    R2PrevTimeStamp,
    RdPrevValue,
    RdPrevTimeStamp,
    CarryFlag,
    XorMultiplicity,
}

impl ColumnNameItem for RegisterMachineColumns {
    type Iter = RegisterMachineColumnsIter;

    fn items() -> Self::Iter {
        Self::iter()
    }

    fn size(&self) -> usize {
        use RegisterMachineColumns::*;

        match self {
            Clk => WORD_SIZE,
            ClkCarryFlag => WORD_SIZE,
            Pc => WORD_SIZE,
            PcCarryFlag => WORD_SIZE,
            IsAdd => 1,
            IsSub => 1,
            IsXor => 1,
            R1Idx => 1,
            R2Idx => 1,
            RdIdx => 1,
            RdIdxNonzero => 1,
            RdIdxNonzeroW => 1,
            RdIdxNonzeroZ => 1,
            R1Val => WORD_SIZE,
            R2Val => WORD_SIZE,
            RdVal => WORD_SIZE,
            RdValWritten => WORD_SIZE,
            R1PrevTimeStamp => WORD_SIZE,
            R1PrevValue => WORD_SIZE,
            R2PrevTimeStamp => WORD_SIZE,
            R2PrevValue => WORD_SIZE,
            RdPrevValue => WORD_SIZE,
            RdPrevTimeStamp => WORD_SIZE,
            CarryFlag => WORD_SIZE,
            XorMultiplicity => 1,
            // Avoid _ and let the compiler detect missing entries.
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Instruction {
    ADD,
    SUB,
    XOR,
}

impl Distribution<Instruction> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Instruction {
        match rng.gen_range(0..3) {
            0 => Instruction::ADD,
            1 => Instruction::SUB,
            _ => Instruction::XOR,
        }
    }
}
