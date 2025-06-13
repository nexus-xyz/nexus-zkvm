use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "register_memory"]
pub enum PreprocessedColumn {
    /// The current execution time
    // TODO: reuse cpu clk column
    #[size = 2]
    Clk,
    /// Current timestamp for register reg1-addr
    #[size = 4]
    Reg1TsCur,
    /// Current timestamp for register reg2-addr
    #[size = 4]
    Reg2TsCur,
    /// Current timestamp for register reg3-addr
    #[size = 4]
    Reg3TsCur,
}

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Address of register b
    #[size = 1]
    Reg1Addr,
    /// Address of register c, or an immediate value. In case of immediate, reg2-accessed is set to zero, and the
    /// value is only used for eliminating the tuple provided by cpu.
    #[size = 1]
    Reg2Addr,
    /// Address of register a
    #[size = 1]
    Reg3Addr,
    /// Contents of register reg1-addr
    #[size = 4]
    Reg1Val,
    /// Contents of register reg2-addr
    #[size = 4]
    Reg2Val,
    /// Proposed contents for register reg3-addr
    #[size = 4]
    Reg3Val,

    // columns for updating reg3-addr value
    /// Previous contents of register reg3-addr
    #[size = 4]
    Reg3ValPrev,
    /// Current contents of register reg3-addr
    #[size = 4]
    Reg3ValCur,
    /// Auxiliary flag, reg3-val-effective-flag = 0 indicates reg3-addr is zero
    #[size = 1]
    Reg3ValEffectiveFlag,
    /// Non-zero auxiliary variable used to handle the case where reg3-addr = 0
    #[size = 1]
    Reg3ValEffectiveFlagAux,
    /// Non-zero auxiliary variable used to handle the case where reg3-addr = 0
    #[size = 1]
    Reg3ValEffectiveFlagAuxInv,

    /// Previous timestamp for register reg1-addr
    #[size = 4]
    Reg1TsPrev,
    /// Previous timestamp for register reg2-addr
    #[size = 4]
    Reg2TsPrev,
    /// Previous timestamp for register reg3-addr
    #[size = 4]
    Reg3TsPrev,
    /// Binary flag indicating whether the set of trace elements (reg1-addr, reg1-val, reg1-ts-cur, reg1-ts-prev) is being used
    #[size = 1]
    Reg1Accessed,
    /// Binary flag indicating whether the set of trace elements (reg2-addr, reg2-val, reg2-ts-cur, reg2-ts-prev) is being used
    #[size = 1]
    Reg2Accessed,
    /// Binary flag indicating whether the set of trace elements (reg3-addr, reg3-val-cur, reg3-ts-cur, reg3-val-prev, reg3-ts-prev) is being used
    #[size = 1]
    Reg3Accessed,
    /// Binary value to indicate if the operation on register reg3-addr is a read or write
    #[size = 1]
    Reg3Write,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,

    // columns for constraining timestamps
    /// Helper columns used for range checks for reg1-ts-prev
    #[size = 4]
    Reg1TsPrevAux,
    /// Helper columns used for range checks for reg2-ts-prev
    #[size = 4]
    Reg2TsPrevAux,
    /// Helper columns used for range checks for reg3-ts-prev
    #[size = 4]
    Reg3TsPrevAux,
    /// Borrow for subtracting timestamps of reg1
    #[size = 1]
    H1AuxBorrow,
    /// Borrow for subtracting timestamps of reg2
    #[size = 1]
    H2AuxBorrow,
    /// Borrow for subtracting timestamps of reg3
    #[size = 1]
    H3AuxBorrow,
}
