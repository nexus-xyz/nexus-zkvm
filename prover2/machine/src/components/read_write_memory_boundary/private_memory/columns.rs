use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The timestamp associated with the last access to address ram-init-final-addr  
    #[size = 2]
    RamTsFinal,
    /// Final value stored at `address`
    #[size = 1]
    RamValFinal,
    /// Current constrained memory address.
    #[size = 4]
    CurrAddress,
    /// Next memory address, enforced to be strictly greater than `curr_addr`
    #[size = 4]
    NextAddress,
    /// `curr_addr` - `next_addr`
    #[size = 4]
    Diff,
    /// First borrow bit in subtraction, the second one is a constant 1.
    #[size = 1]
    Borrow,
    /// Flag indicating the address at the current row is not used
    #[size = 1]
    IsPad,
    /// Multiplicity for the number of reads of the address
    #[size = 1]
    MultiplicityRead,
    /// Multiplicity for the number of writes to the address
    #[size = 1]
    MultiplicityWrite,
}
