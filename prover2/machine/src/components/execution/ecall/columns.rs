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
    #[size = 2]
    BVal,
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
    /// Binary flag to indicate a system-call instruction used for obtaining a cycle count
    #[size = 1]
    IsSysCycleCount,
    /// Binary flag to indicate a system-call instruction used for debugging
    #[size = 1]
    IsSysDebug,
    /// Binary flag to indicate a system-call instruction used for halting
    #[size = 1]
    IsSysHalt,
    /// Binary flag to indicate a system-call instruction used for overwriting the heap pointer
    #[size = 1]
    IsSysHeapReset,
    /// Binary flag to indicate a system-call instruction used for reading a private input
    #[size = 1]
    IsSysPrivInput,
    /// Binary flag to indicate a system-call instruction used for overwriting the stack pointer
    #[size = 1]
    IsSysStackReset,
    /// Boolean flag on whether the row is an ECALL_MADVISE (Heap Allocation)
    #[size = 1]
    IsSysMemoryAdvise,
    /// Flag indicating whether register 3 is accessed
    #[size = 1]
    Reg3Accessed,
}
