use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn, LitStr};

pub fn derive(attr: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);
    let vis = input_fn.vis;
    let sig = input_fn.sig;
    let block = input_fn.block;

    let file_name = if attr.is_empty() {
        let function_name = format!("{}.pb", sig.ident.to_string());
        LitStr::new(&function_name, Span::call_site())
    } else {
        parse_macro_input!(attr as LitStr)
    };

    let found_crate = crate_name("nexus-profiler").expect("profiler is not in `Cargo.toml`");

    let profiler = match found_crate {
        FoundCrate::Itself => quote!(crate::profiler),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!( #ident::profiler )
        }
    };

    let output: proc_macro2::TokenStream = quote! {
        #vis #sig {
            let guard = #profiler::pprof_start();
            let result = (|| #block)();
            #profiler::pprof_end(guard, #file_name);
            result
        }
    };

    output.into()
}
