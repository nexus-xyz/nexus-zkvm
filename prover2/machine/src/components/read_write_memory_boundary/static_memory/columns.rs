use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "static_memory_boundary"]
pub enum PreprocessedColumn {
    /// A flag indicating whether the address on the current row is part of static memory
    #[size = 1]
    IsStaticAddr,
    /// Memory address in the static memory segment
    #[size = 4]
    Address,
    /// Initial 8bit value at `address`, can be non-zero
    #[size = 1]
    InitVal,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The timestamp associated with the last access to address
    #[size = 2]
    RamTsFinal,
    /// Final value stored at `address`
    #[size = 1]
    RamValFinal,
    /// Multiplicity for the number of reads of the address
    #[size = 1]
    MultiplicityRead,
    /// Multiplicity for the number of writes to the address
    #[size = 1]
    MultiplicityWrite,
}
