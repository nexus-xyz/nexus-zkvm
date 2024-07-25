use proc_macro::TokenStream;
use quote::quote;

mod io;
mod entry;
mod parse_args;

#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {

    let segments = vec![
        entry::main(args.into(), input.into())
            .unwrap_or_else(|err| err.into_compile_error().into()),
        io::setup()
            .unwrap_or_else(|err| err.into_compile_error().into()),
    ];

    quote! {
        #(#segments)*
    }.into()
}
