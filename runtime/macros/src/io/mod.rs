use proc_macro2::TokenStream;
use quote::quote;
use syn::Error;

#[cfg(not(feature = "jolt-io"))]
pub fn setup() -> Result<TokenStream, Error> {
    Ok(quote! {})
}

mod jolt;

#[cfg(feature = "jolt-io")]
pub use jolt::setup;
