#![allow(clippy::enum_variant_names)]
use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "rw_memory_boundary"]
pub enum PreprocessedColumn {
    /// A flag indicating whether (pub-io-addr, pub-in-val) on the current row is considered as public input  
    #[size = 1]
    PubInFlag,
    /// The same value as in ram-init-final-addr but only for public input and output  
    #[size = 4]
    PubIoAddr,
    /// 8-bit values of the public input, given byte-wise  
    #[size = 1]
    PubInVal,
    /// 8-bit values of the public output, given byte-wise  
    #[size = 1]
    PubOutVal,
    /// Flag indicating whether (pub-io-addr, pub-out-val) on the current row is considered as public output  
    #[size = 1]
    PubOutFlag,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The memory address given for each byte in the RAM ever touched or relevant for public I/O  
    #[size = 4]
    RamInitFinalAddr,
    /// 8-bit values of the final RAM, given byte-wise  
    #[size = 1]
    RamValFinal,
    /// A helper column containing 8-bit values of the initial RAM  
    #[size = 1]
    RamValInit,
    /// The timestamp associated with the last access to address ram-init-final-addr  
    #[size = 4]
    RamTsFinal,
    /// A flag indicating whether ram-final, ram-init columns on the current row are being used  
    #[size = 1]
    RamInitFinalFlag,
}
