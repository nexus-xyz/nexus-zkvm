use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// A 32-bit word specifying the value of operand op-a represented by four 8-bit limbs
    #[size = 4]
    AVal,
    /// A 32-bit word specifying the value of operand op-b represented by four 8-bit limbs
    #[size = 4]
    BVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The next value of the program counter register after the execution
    #[size = 2]
    PcNext,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Helper variables to implement the BEQ/BNE functionality
    #[size = 2]
    HCarry,

    // helper columns for enforcing register values equality
    #[size = 1]
    HNeq12Flag,
    #[size = 1]
    HNeq12FlagAux,
    #[size = 1]
    HNeq12FlagAuxInv,
    #[size = 1]
    HNeq34Flag,
    #[size = 1]
    HNeq34FlagAux,
    #[size = 1]
    HNeq34FlagAuxInv,
    #[size = 1]
    HNeqFlag,
}
