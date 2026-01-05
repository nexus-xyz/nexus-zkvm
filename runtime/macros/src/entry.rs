use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, ItemFn};

pub fn main(_args: TokenStream, input: TokenStream) -> Result<TokenStream, Error> {
    let func: ItemFn = syn::parse2(input)?;
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
    if fn_sig.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &fn_sig.generics.where_clause,
            "`main` function is not allowed to have a `where` clause",
        ));
    }
    if !fn_sig.inputs.is_empty() {
        return Err(Error::new_spanned(
            &fn_sig.inputs,
            "`main` function arguments must each have an associated input handler",
        ));
    }
    if let syn::ReturnType::Type(_, _ty) = &fn_sig.output {
        return Err(Error::new_spanned(
            &fn_sig.output,
            "`main` function output must have an associated output handler",
        ));
    }

    Ok(quote! {
        const _: fn() = main;

        #[cfg_attr(target_arch = "riscv32", no_mangle)]
        #[allow(unused)]
        #func
    })
}
