use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn};

use super::parse_args::parse_memory_limit;

pub fn main(args: TokenStream, input: TokenStream) -> Result<TokenStream, Error> {
    let func: ItemFn = syn::parse2(input)?;
    let memlimit = parse_memory_limit(args.clone())?;

    #[cfg(feature = "jolt-io")]
    if memlimit != -1 {
        return Err(Error::new_spanned(
            &args,
            "compiling for jolt does not permit customizing the memory limit by macro",
        ));
    }

    let fn_sig = &func.sig;
    if &fn_sig.ident != "main" {
        return Err(Error::new_spanned(
            &fn_sig.ident,
            "function name must be `main`",
        ));
    }
    if fn_sig.asyncness.is_some() {
        return Err(Error::new_spanned(
            fn_sig,
            "`main` function is not allowed to be `async`",
        ));
    }
    if !fn_sig.generics.params.empty_or_trailing() {
        return Err(Error::new_spanned(
            &fn_sig.generics,
            "`main` function is not allowed to have generic parameters",
        ));
    }
    if func.sig.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &fn_sig.generics.where_clause,
            "`main` function is not allowed to have a `where` clause",
        ));
    }

    Ok(quote! {
        const _: fn() = main;

        #[cfg_attr(target_arch = "riscv32", no_mangle)]
        #[allow(unused)]
        #func

        #[cfg(target_arch = "riscv32")]
        #[doc(hidden)]
        mod __private {
            #[no_mangle]
            pub fn get_stack_size() -> i32 {
                #memlimit
            }
        }
    })
}
