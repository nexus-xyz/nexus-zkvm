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
use syn::{parse, spanned::Spanned, FnArg, ItemFn, ItemStruct, Lit, NestedMeta, Meta, PathArguments, ReturnType, Type, Visibility};

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    let alt = input.clone();

    let f = parse_macro_input!(input as ItemFn);

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

    let mut memset: Option<usize> = None;
    let e = parse::Error::new(Span::call_site(), "Invalid main macro arguments, the only supported argument is of the form main(memset(N))");

    if !args.is_empty() {
        let c = parse_macro_input!(alt as ItemStruct);

        for attr in &c.attrs {
            if attr.path.is_ident("main") {
                let meta = attr.parse_meta();

                if meta.is_err() {
                    return e.to_compile_error().into();
                }

                let meta = meta.unwrap();

                if meta.path().is_ident("memset") {
                    if let Meta::List(list) = meta {
                        let val = list.nested.first();

                        if val.is_some() {
                            if let NestedMeta::Lit(Lit::Int(lit)) = val.unwrap() {
                                let n = lit.base10_parse();

                                if n.is_ok() {
                                    memset = Some(n.unwrap());
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            return e.to_compile_error().into();
        }
    };

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
