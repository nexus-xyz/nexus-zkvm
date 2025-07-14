use nexus_vm_prover_air_column::{empty::EmptyPreprocessedColumn, AirColumn};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

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
    /// The helper bits to compute the program counter update. The second pair of bytes is added together,
    /// the third bit is not needed.
    #[size = 3]
    PcCarry,
    /// Second byte in little endian representation of the next program counter
    #[size = 1]
    PcNext8_15,
    // pc_next0_7 = pc_rem_aux (masked bit) + 2 * pc_qt_aux
    #[size = 1]
    PcRemAux,
    #[size = 1]
    PcQtAux,
    /// Higher 16 bits of the next value of the program counter register after the execution
    #[size = 1]
    PcNextHigh,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,
    /// Helper variables to implement the JALR functionality
    #[size = 2]
    HCarry,
}
