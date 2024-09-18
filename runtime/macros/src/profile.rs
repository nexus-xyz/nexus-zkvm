use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, ItemFn};

pub fn profile(input: TokenStream) -> TokenStream {
    let item: ItemFn = parse2(input).expect("Invalid code block");

    let ItemFn {
        vis: visibility,
        sig: signature,
        block,
        ..
    } = item;

    let name: &syn::Ident = &signature.ident;
    let nexus_rt = super::get_nexus_rt_ident();

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
