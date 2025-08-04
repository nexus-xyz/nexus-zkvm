use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu_boundary"]
pub enum PreprocessedColumn {
    /// Multiplicity for boundary lookup. -1 on the second row and 0 everywhere else.
    #[size = 1]
    FinalMultiplicity,
    /// Multiplicity for initial lookup, 1 on the first row and 0 everywhere else.
    #[size = 1]
    InitMultiplicity,
    /// Initial value of the program counter.
    #[size = 2]
    InitPc,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Final value of the program counter.
    #[size = 2]
    FinalPc,
    /// Initial and final values of the clock. The initial value is enforced to equal 1
    /// in the preprocessed trace of the CPU component.
    #[size = 2]
    Clk,
}
