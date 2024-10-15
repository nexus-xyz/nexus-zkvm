use proc_macro::TokenStream;

mod column_enum;

/// Implements public `size` and `offset` **const** methods on a unit-variant
/// enum, and defines `COLUMNS_NUM` constant.
///
/// These are usual enum methods and not part of any traits, because
/// traits only allow associated constants, not constant functions.
///
/// However, constant functions are useful for having compile-time dimensions
/// when indexing trace columns.
///
/// ```
/// use nexus_vm_prover_macros::ColumnsEnum;
/// // Columns layout:
/// // A0 B0 B1 B2 B3 C0 C1 C2 C3 C4
/// #[derive(Copy, Clone, ColumnsEnum)]
/// enum Column {
///     #[size = 1] // 1 column starting at offset 0.   
///     A,
///     #[size = 4] // 4 columns starting at offset 1.
///     B,
///     #[size = 5] // 5 columns starting at offset 5.
///     C,
/// }
/// assert_eq!(Column::COLUMNS_NUM, 1 + 4 + 5);
/// ```
#[proc_macro_derive(ColumnsEnum, attributes(size))]
pub fn derive_columns_enum(input: TokenStream) -> TokenStream {
    column_enum::generate_impls(input.into())
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}
