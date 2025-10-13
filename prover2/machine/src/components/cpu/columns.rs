use stwo::core::fields::m31::BaseField;

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use nexus_vm_prover_trace::eval::TraceEval;
use stwo_constraint_framework::EvalAtRow;

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {
    /// The current execution time
    #[size = 2]
    Clk,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Second byte in little endian representation of the program counter
    #[size = 1]
    PcNext8_15,
    /// Higher 16 bits of the program counter
    #[size = 1]
    PcHigh,
    /// Bits[2..=8] of the program counter
    #[size = 1]
    PcAux,
    /// A selector flag which is used for padding, not a computational step
    #[size = 1]
    IsPad,
}
