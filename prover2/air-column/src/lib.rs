//! Trait definition and procedural macros for deriving the implementation for unit-variant enums.
//!
//! ### Syntax
//!
//! ```ignore
//! use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
//! // Columns layout:
//! // PC0 PC1 PC2 PC3 FLAG0 AUX0 AUX1
//! #[derive(Copy, Clone, AirColumn)]
//! enum Column {
//!     #[size = 4]         // 4 columns starting at offset 0.  
//!     #[mask_next_row]    // implement access to next row during constraints evaluation.
//!     Pc,
//!     #[size = 1]         // 1 column starting at offset 4.
//!     Flag,
//!     #[size = 2]         // 2 columns starting at offset 5.
//!     Aux,
//! }
//! assert_eq!(<Column as AirColumn>::COLUMNS_NUM, 4 + 1 + 2);
//!
//! // Columns layout:
//! // IS_FIRST0 CLK0 CLK1 CLK2 CLK3
//! #[derive(Copy, Clone, PreprocessedAirColumn)]
//! enum PreprocessedColumn {
//!     // #[mask_next_row] // next row attribute would cause a compile error
//!     #[size = 1]         // 1 column starting at offset 0.  
//!     IsFirst,
//!     #[size = 4]         // 4 columns starting at offset 1.
//!     Clk,
//! }
//! ```
use std::fmt;

pub use nexus_vm_prover_air_column_derive::{AirColumn, PreprocessedAirColumn};

pub mod empty;

/// Trait used for column indexing during constraints evaluation and trace generation.
pub trait AirColumn: 'static + Copy + fmt::Debug {
    /// Total number of columns in the trace.
    const COLUMNS_NUM: usize;

    /// Static slice of all enum variants.
    const ALL_VARIANTS: &'static [Self];

    /// Returns the number of columns corresponding to the variant.
    fn size(self) -> usize;

    /// Returns the starting offset for the variant.
    fn offset(self) -> usize;

    /// Returns `true` if the column requires mask values at the offset [0, 1], or in other words,
    /// constraints require both values at the current **and** next row, e.g. for constraining next
    /// pc value.
    fn mask_next_row(self) -> bool;
}

/// An extension of [`AirColumn`] that implement preprocessed id.
///
/// Note that unlike the super trait preprocessed columns do not support next row mask.
pub trait PreprocessedAirColumn: AirColumn {
    /// Static slice of all preprocessed columns identifiers.
    ///
    /// A slice `&<Self as PreprocessedAirColumn>::PREPROCESSED_IDS[self.offset()..self.offset() + self.size()]`
    /// corresponds to preprocessed ids of a variant, which can be used for shared column access.
    const PREPROCESSED_IDS: &'static [&'static str];
}
