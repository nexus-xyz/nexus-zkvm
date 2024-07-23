use proc_macro::TokenStream;

#[cfg(not(feature = "jolt-io"))]
pub fn setup() -> TokenStream {
    quote! {}
}

mod jolt;

#[cfg(feature = "jolt-io")]
pub use jolt::setup;
