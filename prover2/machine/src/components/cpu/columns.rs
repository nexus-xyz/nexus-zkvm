use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
pub enum PreprocessedColumn {
    /// The current execution time
    #[size = 2]
    Clk,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current value of the program counter register
    #[size = 4]
    Pc,
    /// Auxiliary variable used for program counter arithmetic
    #[size = 1]
    PcAux,
    /// The opcode defining the instruction
    #[size = 1]
    Opcode,
    /// The value of operand op-a
    #[size = 4]
    AVal,
    /// The value of operand op-b
    #[size = 4]
    BVal,
    /// The value of operand op-c
    #[size = 4]
    CVal,
    // Instruction flags
    /// Selector flag which indicates an ADD operation
    #[size = 1]
    IsAdd,
    /// Selector flag which indicates an ADD operation
    #[size = 1]
    IsAddI,
    /// A selector flag which is used for padding, not a computational step
    #[size = 1]
    IsPad,
}
