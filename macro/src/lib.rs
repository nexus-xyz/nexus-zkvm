use proc_macro::TokenStream;
mod pprof;

#[proc_macro_attribute]
pub fn profile(attr: TokenStream, input: TokenStream) -> TokenStream {
    pprof::derive(attr, input)
}
