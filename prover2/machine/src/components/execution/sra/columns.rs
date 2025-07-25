use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

use crate::components::execution::common::derive_execution_column;

pub type PreprocessedColumn = EmptyPreprocessedColumn;

derive_execution_column! { Column }

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time represented by two 16-bit limbs
    #[size = 2]
    Clk,
    /// The next execution time represented by two 16-bit limbs
    #[size = 2]
    ClkNext,
    /// The helper bit to compute the next clock value
    #[size = 1]
    ClkCarry,
    /// A 32-bit word specifying the value of operand op-a represented by four 8-bit limbs
    #[size = 4]
    AVal,
    /// A 32-bit word specifying the value of operand op-b represented by four 8-bit limbs
    #[size = 4]
    BVal,
    /// A 32-bit word specifying the value of operand op-c represented by four 8-bit limbs
    #[size = 4]
    CVal,
    /// The current value of the program counter register
    #[size = 2]
    Pc,
    /// The helper bits to compute the program counter update
    #[size = 1]
    PcCarry,
    /// The next value of the program counter register after the execution
    #[size = 2]
    PcNext,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,

    // helper variables used for constraining SRA
    /// 1 << (imm & 0b111)
    #[size = 1]
    Exp3,
    #[size = 1]
    Exp3Aux,
    #[size = 4]
    Qt,
    #[size = 4]
    Rem,
    #[size = 4]
    RemAux,
    /// Highest bit of the immediate
    #[size = 1]
    HRem,
    #[size = 1]
    HRemB,
    #[size = 1]
    HSgnB,
    #[size = 1]
    SraMask,
    #[size = 4]
    Srl,
    /// Shift bits `imm[0]` through `imm[4]` extracted from c-val
    #[size = 5]
    Sh,
}
