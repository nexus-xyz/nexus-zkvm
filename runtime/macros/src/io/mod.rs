#[cfg(not(feature = "jolt-io"))]
mod base {
    use proc_macro2::TokenStream;
    use quote::quote;
    use syn::Error;

    pub fn setup() -> Result<TokenStream, Error> {
        Ok(quote! {})
    }
}

#[cfg(not(feature = "jolt-io"))]
pub use base::setup;

#[cfg(feature = "jolt-io")]
mod jolt;

#[cfg(feature = "jolt-io")]
pub use jolt::setup;
