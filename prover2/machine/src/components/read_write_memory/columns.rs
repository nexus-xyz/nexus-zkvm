use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use nexus_vm_prover_air_column::{
    empty::EmptyPreprocessedColumn, AirColumn, PreprocessedAirColumn,
};
use nexus_vm_prover_trace::{
    component::ComponentTrace, eval::TraceEval, original_base_column, trace_eval,
    virtual_column::VirtualColumn,
};

pub type PreprocessedColumn = EmptyPreprocessedColumn;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The current execution time
    #[size = 2]
    Clk,
    /// Memory base address
    #[size = 4]
    RamBaseAddr,
    /// 8-bit value used to update address ram-base-addr
    #[size = 1]
    Ram1ValCur,
    /// 8-bit value used to update address ram-base-addr + 1
    #[size = 1]
    Ram2ValCur,
    /// 8-bit value used to update address ram-base-addr + 2
    #[size = 1]
    Ram3ValCur,
    /// 8-bit value used to update address ram-base-addr + 3
    #[size = 1]
    Ram4ValCur,
    /// Previous 8-bit value stored at address ram-base-addr
    #[size = 1]
    Ram1ValPrev,
    /// Previous 8-bit value stored at address ram-base-addr + 1
    #[size = 1]
    Ram2ValPrev,
    /// Previous 8-bit value stored at address ram-base-addr + 2
    #[size = 1]
    Ram3ValPrev,
    /// Previous 8-bit value stored at address ram-base-addr + 3
    #[size = 1]
    Ram4ValPrev,
    /// Previous timestamp for address ram-base-addr
    #[size = 4]
    Ram1TsPrev,
    /// Previous timestamp for address ram-base-addr + 1
    #[size = 4]
    Ram2TsPrev,
    /// Previous timestamp for address ram-base-addr + 2
    #[size = 4]
    Ram3TsPrev,
    /// Previous timestamp for address ram-base-addr + 3
    #[size = 4]
    Ram4TsPrev,
    /// Binary flag indicating whether address in ram-base-addr is being accessed
    #[size = 1]
    Ram1Accessed,
    /// Binary flag indicating whether address in ram-base-addr + 1 is being accessed
    #[size = 1]
    Ram2Accessed,
    /// Binary flag indicating whether the address pair ram-base-addr + 2 and +3 is being accessed
    #[size = 1]
    Ram3_4Accessed,
    /// Binary flag indicating whether the current instruction is a store (memory write).
    #[size = 1]
    RamWrite,
    /// Binary value to indicate if the row is a padding row
    #[size = 1]
    IsLocalPad,

    // Helper columns
    /// Helper columns used for range checks for ram1-ts-prev
    #[size = 4]
    Ram1TsPrevAux,
    /// Helper columns used for range checks for ram2-ts-prev
    #[size = 4]
    Ram2TsPrevAux,
    /// Helper columns used for range checks for ram3-ts-prev
    #[size = 4]
    Ram3TsPrevAux,
    /// Helper columns used for range checks for ram4-ts-prev
    #[size = 4]
    Ram4TsPrevAux,
    /// Helper columns used to handle borrows for ram1-ts-prev
    #[size = 1]
    Ram1TsPrevBorrow,
    /// Helper columns used to handle borrows for ram2-ts-prev
    #[size = 1]
    Ram2TsPrevBorrow,
    /// Helper columns used to handle borrows for ram3-ts-prev
    #[size = 1]
    Ram3TsPrevBorrow,
    /// Helper columns used to handle borrows for ram4-ts-prev
    #[size = 1]
    Ram4TsPrevBorrow,
}

impl Column {
    pub(super) const fn address_offset(self) -> u32 {
        match self {
            Column::Ram1ValPrev | Column::Ram1ValCur => 0,
            Column::Ram2ValPrev | Column::Ram2ValCur => 1,
            Column::Ram3ValPrev | Column::Ram3ValCur => 2,
            Column::Ram4ValPrev | Column::Ram4ValCur => 3,
            _ => panic!("invalid column"),
        }
    }
}

/// Least significant base address byte with an offset.
pub struct ShiftedBaseAddr {
    pub offset: u32,
}

impl VirtualColumn for ShiftedBaseAddr {
    type Column = Column;

    fn eval<E: EvalAtRow, P: PreprocessedAirColumn>(
        &self,
        trace_eval: &TraceEval<P, Self::Column, E>,
    ) -> E::F {
        let mut addr_byte = trace_eval!(trace_eval, Column::RamBaseAddr)[0].clone();
        addr_byte += BaseField::from(self.offset);
        addr_byte
    }

    fn combine_at_row(&self, component_trace: &ComponentTrace, vec_idx: usize) -> PackedBaseField {
        let addr_byte = original_base_column!(component_trace, Column::RamBaseAddr)[0].clone();
        addr_byte.at(vec_idx) + BaseField::from(self.offset)
    }
}
