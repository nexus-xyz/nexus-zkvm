use proc_macro::TokenStream;

mod derive_impl;
mod utils;

#[proc_macro_derive(AirColumn, attributes(size, mask_next_row))]
pub fn derive_air_column(input: TokenStream) -> TokenStream {
    derive_impl::generate_impl(input.into(), false)
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}

#[proc_macro_derive(PreprocessedAirColumn, attributes(size, preprocessed_prefix))]
pub fn derive_preprocessed_air_column(input: TokenStream) -> TokenStream {
    derive_impl::generate_impl(input.into(), true)
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}
