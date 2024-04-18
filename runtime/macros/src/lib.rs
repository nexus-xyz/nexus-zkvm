// based on riscv-rt

#![deny(warnings)]

extern crate proc_macro;
#[macro_use]
extern crate quote;
extern crate core;
extern crate proc_macro2;
#[macro_use]
extern crate syn;

use proc_macro2::Span;
use syn::{
    parse, punctuated::Punctuated, spanned::Spanned, FnArg, ItemFn, Lit, Meta, NestedMeta,
    PathArguments, ReturnType, Type, Visibility,
};

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    let f = parse_macro_input!(input as ItemFn);
    let a = parse_macro_input!(args with Punctuated::<Meta, syn::Token![,]>::parse_terminated);

    // check the function arguments
    if f.sig.inputs.len() > 3 {
        return parse::Error::new(
            f.sig.inputs.last().unwrap().span(),
            "function has too many arguments",
        )
        .to_compile_error()
        .into();
    }
    for arg in &f.sig.inputs {
        match arg {
            FnArg::Receiver(_) => {
                return parse::Error::new(arg.span(), "invalid argument")
                    .to_compile_error()
                    .into();
            }
            FnArg::Typed(t) => {
                if !is_simple_type(&t.ty, "u32") {
                    return parse::Error::new(t.ty.span(), "argument type must be usize")
                        .to_compile_error()
                        .into();
                }
            }
        }
    }

    // check the function signature
    let valid_signature = f.sig.constness.is_none()
        && f.sig.asyncness.is_none()
        && f.vis == Visibility::Inherited
        && f.sig.abi.is_none()
        && f.sig.generics.params.is_empty()
        && f.sig.generics.where_clause.is_none()
        && f.sig.variadic.is_none()
        && match f.sig.output {
            ReturnType::Default => true,
            ReturnType::Type(_, ref ty) => is_simple_type(ty, "u32"),
        };

    if !valid_signature {
        return parse::Error::new(
            f.span(),
            "function must have signature `fn([arg0: u32, ...]) [-> u32]`",
        )
        .to_compile_error()
        .into();
    }

    let mut memset: i32 = -1;
    let e = parse::Error::new(Span::call_site(), "Invalid macro argument: the only supported argument is of the form main(memset(N)) for N > 0");

    if let Some(e) = (|| -> Result<(), parse::Error> {
        if !a.is_empty() {
            for arg in a {
                if arg.path().is_ident("memset") {
                    if let Meta::List(list) = arg {
                        let val = list.nested.first();

                        if val.is_some() {
                            if let NestedMeta::Lit(Lit::Int(lit)) = val.unwrap() {
                                let n = lit.base10_parse::<i32>();
                                if n.is_ok() {
                                    memset = n.unwrap() * 0x100000;
                                    if memset <= 0 {
                                        return Err(e);
                                    }

                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
            return Err(e);
        }
        Ok(())
    })()
    .err()
    {
        return e.to_compile_error().into();
    }

    // XXX should we blacklist other attributes?
    let attrs = f.attrs;
    let unsafety = f.sig.unsafety;
    let args = f.sig.inputs;
    let res = f.sig.output;
    let stmts = f.block.stmts;

    quote!(
        #[export_name = "main"]
        #(#attrs)*
        pub #unsafety fn __risc_v_rt__main(#args) #res {
            #(#stmts)*
        }
        #[export_name = "get_stack_size"]
        pub fn __risc_v_rt__get_stack_size() -> i32 {
            #memset
        }
    )
    .into()
}

fn is_simple_type(ty: &Type, name: &str) -> bool {
    if let Type::Path(p) = ty {
        if p.qself.is_none() && p.path.leading_colon.is_none() && p.path.segments.len() == 1 {
            let segment = p.path.segments.first().unwrap();
            if segment.ident == name && segment.arguments == PathArguments::None {
                return true;
            }
        }
    }
    false
}
