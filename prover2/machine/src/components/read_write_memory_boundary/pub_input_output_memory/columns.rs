use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "pub_memory_boundary"]
pub enum PreprocessedColumn {
    /// A flag indicating whether (pub-io-addr, pub-in-val) on the current row is considered as public input  
    #[size = 1]
    PubInFlag,
    /// Flag indicating whether (pub-io-addr, pub-out-val) on the current row is considered as public output  
    #[size = 1]
    PubOutFlag,
    /// The same value as in ram-init-final-addr but only for public input and output  
    #[size = 4]
    PubIoAddr,
    /// 8-bit values of the public input, given byte-wise  
    #[size = 1]
    PubInVal,
    /// 8-bit values of the public output, given byte-wise  
    #[size = 1]
    PubOutVal,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The timestamp associated with the last access to address ram-init-final-addr  
    #[size = 2]
    RamTsFinal,
    /// Multiplicity for the number of reads of the address
    #[size = 1]
    MultiplicityRead,
    /// Multiplicity for the number of writes to the address
    #[size = 1]
    MultiplicityWrite,
}
