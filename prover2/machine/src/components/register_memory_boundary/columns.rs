use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "register_memory_boundary"]
pub enum PreprocessedColumn {
    /// Register address, from 0 to 31
    #[size = 1]
    RegAddr,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Final value of the register
    #[size = 4]
    FinalVal,
    /// Final timestamp of the register
    #[size = 4]
    FinalTs,
}
