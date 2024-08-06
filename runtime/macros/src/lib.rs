use proc_macro::TokenStream;

mod io;
mod entry;
mod parse_args;
mod profile;

#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    entry::main(args.into(), input.into())
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}

#[proc_macro_attribute]
pub fn profile(_attr: TokenStream, item: TokenStream) -> TokenStream {
    profile::profile(_attr.into(), item.into()).into()
}

#[proc_macro_attribute]
pub fn read_segment(args: TokenStream, input: TokenStream) -> TokenStream {
    io::read_segment(args.into(), input.into())
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}

#[proc_macro_attribute]
pub fn write_segment(args: TokenStream, input: TokenStream) -> TokenStream {
    io::write_segment(args.into(), input.into())
        .map(Into::into)
        .unwrap_or_else(|err| err.into_compile_error().into())
}
