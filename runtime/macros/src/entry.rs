use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, ReturnType};

use super::parse_args::parse_memory_limit;

pub fn main(args: TokenStream, input: TokenStream) -> Result<TokenStream, Error> {
    let func: ItemFn = syn::parse2(input)?;
    let memlimit = parse_memory_limit(args)?;

    let ident = &func.sig.ident;
    if &func.sig.ident != "main" {
        return Err(Error::new_spanned(ident, "function name must be `main`"));
    }
    if !func.sig.inputs.is_empty() || func.sig.output != ReturnType::Default {
        // copy default error message
        let message = "`main` function has wrong type\nexpected signature `fn()`";
        return Err(Error::new_spanned(func.sig, message));
    }

    Ok(quote! {
        #[cfg_attr(target_arch = "riscv32", no_mangle)]
        #[allow(unused)]
        #func

        #[cfg(target_arch = "riscv32")]
        #[export_name = "get_stack_size"]
        pub fn __risc_v_rt__get_stack_size() -> i32 {
            #memlimit
        }
    })
}
