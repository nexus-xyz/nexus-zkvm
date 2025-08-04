use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The word-aligned base address associated with a program instruction
    #[size = 2]
    Pc,
    /// The 32-bit instruction word stored at address pc
    #[size = 2]
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
