#![allow(clippy::enum_variant_names)]
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "rw_memory_boundary"]
pub enum PreprocessedColumn {
    /// The memory address given for each 4-byte instruction in the program memory ever touched
    #[size = 2]
    ProgInitBaseAddr,
    /// The 4-byte instruction word stored at address prog-init-base-addr
    #[size = 2]
    ProgValInit,
    /// A flag indicating whether prog-val-init and prog-ctr-final columns on the current row are being used
    #[size = 1]
    ProgInitFlag,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The counter associated with the last access to address prog-init-base-addr
    #[size = 4]
    ProgCtrFinal,
}
