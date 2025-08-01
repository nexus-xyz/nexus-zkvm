use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// The lowest bit of operand op-a
    #[size = 1]
    AVal,
    /// A 32-bit word specifying the value of operand op-b represented by four 8-bit limbs
    #[size = 4]
    BVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The helper bits to compute the program counter update
    #[size = 1]
    PcCarry,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Helper variables to implement the SUB functionality
    #[size = 2]
    HBorrow,
    /// Result of subtracting c-val from b-val
    #[size = 4]
    HRem,
    /// Lower 7 bits of the highest byte of `b-val`
    #[size = 1]
    HRemB,
    /// Lower 7 bits of the highest byte of `c-val`
    #[size = 1]
    HRemC,
    /// Sign bit of the highest byte of `b-val`
    #[size = 1]
    HSgnB,
    /// Sign bit of the highest byte of `c-val`
    #[size = 1]
    HSgnC,
}
