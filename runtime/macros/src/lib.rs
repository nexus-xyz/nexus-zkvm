use proc_macro::TokenStream;

mod entry;
mod parse_args;

#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    entry::main(args.into(), input.into())
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}
