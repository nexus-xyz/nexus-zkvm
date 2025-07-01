#![allow(clippy::enum_variant_names)]
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitwise_multiplicity"]
pub enum PreprocessedColumn {
    /// Four-bit first input operand for the bitwise lookup table
    #[size = 1]
    BVal,
    /// Four-bit second input operand for the bitwise lookup table
    #[size = 1]
    CVal,
    /// Four-bit output of the bitwise AND operation
    #[size = 1]
    BitwiseAndA,
    /// Four-bit output of the bitwise OR operation
    #[size = 1]
    BitwiseOrA,
    /// Four-bit output of the bitwise XOR operation
    #[size = 1]
    BitwiseXorA,
}

/// Multiplicity columns used for bitwise operations lookups.
///
/// Each column tracks how many times tuple (op, b, c, a) is looked up in the trace,
/// where b * 256 + c is the row index.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity column for bitwise-AND check. MultiplicityAnd[b * 256 + c] counts how many times (b & c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityAnd,
    /// Multiplicity column for bitwise-OR check. MultiplicityOr[b * 256 + c] counts how many times (b | c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityOr,
    /// Multiplicity column for bitwise-XOR check. MultiplicityXor[b * 256 + c] counts how many times (b ^ c) is looked up in the entire trace.
    #[size = 1]
    MultiplicityXor,
}
