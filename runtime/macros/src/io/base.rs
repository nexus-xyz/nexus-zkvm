use proc_macro2::TokenStream;
use quote::quote;
use syn::Error;

pub fn setup() -> Result<TokenStream, Error> {
    Ok(quote! {})
}
