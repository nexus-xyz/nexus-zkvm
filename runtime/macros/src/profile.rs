use proc_macro2::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
use syn::{parse2, ItemFn};

fn get_nexus_rt_ident() -> proc_macro2::Ident {
    match crate_name("nexus_rt") {
        Ok(FoundCrate::Name(name)) => format_ident!("{}", name),
        _ => format_ident!("nexus_rt"),
    }
}

pub fn profile(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input: ItemFn = parse2(item).expect("Invalid code block");

    let ItemFn {
        vis: visibility, sig: signature, block, ..
    } = input;

    let name: &syn::Ident = &signature.ident;
    let nexus_rt = get_nexus_rt_ident();

    quote! {
        #visibility #signature {
            #[cfg(feature = "cycles")]
            #nexus_rt::cycle_count_ecall(concat!("^#", file!(), ":", stringify!(#name)));
            let result = (|| #block)();
            #[cfg(feature = "cycles")]
            #nexus_rt::cycle_count_ecall(concat!("$#", file!(), ":", stringify!(#name)));
            result
        }
    }
}
