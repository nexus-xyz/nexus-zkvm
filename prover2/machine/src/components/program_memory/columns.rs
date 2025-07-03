use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

use crate::components::cpu::HalfWord;

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The word-aligned base address associated with a program instruction
    #[size = 4]
    Pc,
    /// The 32-bit instruction word stored at address pc
    #[size = 4]
    InstrVal,
    /// The previous counter value associated with base address pc
    #[size = 4]
    ProgCtrPrev,
    /// The current counter value associated with base address pc
    #[size = 4]
    ProgCtrCur,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,

    // helper trace columns
    /// Carry column for program counter updates
    #[size = 1]
    ProgCtrCarry,
}

pub const PC_LOW: HalfWord<Column> = HalfWord {
    col: Column::Pc,
    idx: 0,
};

pub const PC_HIGH: HalfWord<Column> = HalfWord {
    col: Column::Pc,
    idx: 1,
};
