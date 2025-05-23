use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
pub enum PreprocessedColumn {
    /// Multiplicity for boundary lookup. 1 on the first row, -1 on the second, and 0 everywhere else.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Initial and final values of the program counter.
    #[size = 2]
    Pc,
    /// Initial and final values of the clock. The initial value is enforced to equal 1
    /// in the preprocessed trace of the CPU component.
    #[size = 2]
    Clk,
}
