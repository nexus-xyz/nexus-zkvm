use proc_macro::TokenStream;
use proc_macro2::Ident;
use std::collections::HashSet;

extern crate proc_macro;
use quote::{quote, ToTokens};

use crate::{get_nexus_rt_ident, stream_error};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::Expr::{Path, Tuple};
use syn::__private::TokenStream2;
use syn::{parse_macro_input, Expr, FnArg, ItemFn, PatType, Token, Type};

pub(crate) enum InputType {
    Custom,
    Public,
    Private,
}

pub(crate) enum OutputType {
    Custom,
    Public,
}

pub(crate) fn handle_output(
    args: TokenStream,
    item: TokenStream,
    output_type: OutputType,
) -> TokenStream {
    // Parse the attribute arguments.
    let attr_args = if let Ok(parsed) =
        Punctuated::<syn::Expr, Token![,]>::parse_terminated.parse(args.clone())
    {
        parsed
    } else {
        return stream_error(
            TokenStream2::from(args),
            "Unable to parse attribute arguments.",
        );
    };

    // Parse the function name for custom output.
    let custom_fn_name: Option<Ident> = match output_type {
        OutputType::Custom => {
            let arg_num_error_msg = "Invalid attribute arguments. Ex: To specify that output should be handled by `foo` write `#[nexus_rt::custom_output(foo)]`";
            // This error checking allows us to safely unwrap below.
            if attr_args.len() != 1 {
                return stream_error(&attr_args, arg_num_error_msg);
            }
            // Parse function name.
            if let Path(path) = attr_args.get(0).unwrap() {
                if path.path.segments.len() != 1 {
                    return stream_error(path, arg_num_error_msg);
                }
                Some(path.path.segments.get(0).unwrap().ident.clone())
            } else {
                return stream_error(&attr_args, arg_num_error_msg);
            }
        }
        OutputType::Public => {
            if !attr_args.is_empty() {
                return stream_error(&attr_args, "Invalid attribute arguments. `nexus_rt::public_output` does not take any arguments.");
            }
            None
        }
    };

    // Parse the function signature, function body, and other attributes.
    let ItemFn {
        attrs, sig, block, ..
    } = parse_macro_input!(item as ItemFn);
    let inputs = sig.inputs.clone();
    let fn_name = sig.ident.clone();
    let output: Type = match sig.output {
        syn::ReturnType::Type(_, t) => *t,
        syn::ReturnType::Default => {
            return stream_error(&sig.output, "Expected a return type");
        }
    };

    // Generate the output handler name.
    let nexus_rt = get_nexus_rt_ident();
    let output_fn_full = match output_type {
        OutputType::Public => quote! {
            #nexus_rt::write_public_output::<#output>
        },
        OutputType::Custom => quote! {
            #custom_fn_name
        },
    };

    // Check that the target architecture is riscv32 if doing public output.
    let target_check = if !matches!(output_type, OutputType::Custom) {
        quote! {
            #[cfg(not(target_arch = "riscv32"))]
            compile_error!("NexusVM public output interfaces are not available for native builds, use a custom handler instead. Ex: #[nexus_rt::custom_output(bar)]");
        }
    } else {
        quote! {}
    };

    // Build the output token stream
    let expanded = quote! {
        #target_check
        #(#attrs)*
        fn #fn_name(#inputs) {
            let out = (|| {
                #block
            })();
            #output_fn_full(&out).unwrap_or_else(|e| {
                panic!("Failed to write output: {:?}", e);
            });
        }
    };

    TokenStream::from(expanded)
}

pub(crate) fn handle_input(
    args: TokenStream,
    item: TokenStream,
    input_type: InputType,
) -> TokenStream {
    // Parse the attribute arguments.
    let attr_args = if let Ok(parsed) =
        Punctuated::<syn::Expr, Token![,]>::parse_terminated.parse(args.clone())
    {
        parsed
    } else {
        return stream_error(
            TokenStream2::from(args),
            "Unable to parse attribute arguments.",
        );
    };

    // Parse the function name for custom input.
    let (custom_fn_name, attr_inputs): (Option<Ident>, Punctuated<Expr, Comma>) = match input_type {
        InputType::Custom => {
            let invalid_attr_err = "Invalid attribute arguments. Ex: To specify that `(x,y,z)` are custom inputs supplied by `fizz` write `#[nexus_rt::custom_input((x,y,z), fizz)]`";
            // This error checking allows us to safely unwrap below.
            if attr_args.len() != 2 {
                return stream_error(&attr_args, invalid_attr_err);
            }
            // Parse function name.
            let name: Ident = if let Path(path) = attr_args.get(1).unwrap() {
                if path.path.segments.len() != 1 {
                    return stream_error(path, invalid_attr_err);
                }
                path.path.segments.get(0).unwrap().ident.clone()
            } else {
                return stream_error(&attr_args, invalid_attr_err);
            };

            // Parse variables that need to be handled.
            if let Tuple(expr) = attr_args.get(0).unwrap() {
                (Some(name), expr.elems.clone())
            } else if let Expr::Paren(expr) = attr_args.get(0).unwrap() {
                if let Path(id) = *expr.expr.clone() {
                    let mut p: Punctuated<Expr, Comma> = Punctuated::new();
                    p.insert(0, Path(id.clone()));
                    (Some(name), p)
                } else {
                    let got = attr_args.get(0).unwrap().to_token_stream().to_string();
                    return stream_error(expr, format!("Expected input variable, got {}.", got));
                }
            } else if let Path(id) = attr_args.get(0).unwrap() {
                let mut p: Punctuated<Expr, Comma> = Punctuated::new();
                p.insert(0, Path(id.clone()));
                (Some(name), p)
            } else {
                let got = attr_args.get(0).unwrap().to_token_stream().to_string();
                return stream_error(
                    &attr_args,
                    format!("Expected a tuple of input types, got type {}.", got),
                );
            }
        }
        InputType::Public | InputType::Private => (None, attr_args.clone()),
    };

    // Check that the set of input variables is non-empty.
    if attr_inputs.is_empty() {
        let input_type_label = match input_type {
            InputType::Public => "public input",
            InputType::Private => "private input",
            InputType::Custom => "input",
        };
        return stream_error(
            &attr_args,
            format!("Expected at least one {}.", input_type_label),
        );
    }

    // Parse the input variables.
    let mut public_inputs: HashSet<Ident> = HashSet::new();
    for x in attr_inputs.iter() {
        if let Path(id) = x {
            if id.path.segments.len() != 1 {
                return stream_error(id, "Expected an identifier.");
            }
            let name = id.path.segments.get(0).unwrap().ident.clone();
            if public_inputs.contains(&name) {
                return stream_error(&attr_args, format!("Duplicate public input: {}.", name));
            }
            public_inputs.insert(name);
        } else {
            return stream_error(x, "Expected an identifier.");
        }
    }

    // Extract the function signature and body.
    let ItemFn {
        attrs, sig, block, ..
    } = parse_macro_input!(item as ItemFn);
    let fn_name = sig.ident.clone();
    let output = sig.output.clone();

    // Create list of inputs that need to be handled and their corresponding types.
    let mut inputs: Vec<Ident> = Vec::new();
    let mut types: Vec<Type> = Vec::new();
    let mut input_sig: Punctuated<FnArg, Token![,]> = Punctuated::new();
    for arg in sig.inputs.iter() {
        if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
            if let syn::Pat::Ident(pat_ident) = &(**pat) {
                // Remove each input that will be handled by the function specified in the attribute.
                if public_inputs.remove(&pat_ident.ident) {
                    inputs.push(pat_ident.ident.clone());
                    types.push(*ty.clone());
                } else {
                    input_sig.push(arg.clone());
                }
            } else {
                return stream_error(arg, "`self` is not allowed as a function argument.");
            }
        } else {
            return stream_error(arg, "Expected typed function arguments.");
        }
    }

    // Check that all inputs listed in the attribute are present in the function signature.
    if !public_inputs.is_empty() {
        let mut input_names: Vec<String> = public_inputs.iter().map(|id| id.to_string()).collect();
        input_names.sort();
        let input_list = input_names.join(", ");
        return stream_error(
            &sig.inputs,
            format!(
                "Provided public input does not appear in the function signature: {}",
                input_list
            ),
        );
    }

    // Generate the input handler name.
    let nexus_rt = get_nexus_rt_ident();
    let input_handler = match input_type {
        InputType::Public => quote! {
            #nexus_rt::read_public_input::<(#(#types),*)>
        },
        InputType::Private => quote! {
            #nexus_rt::read_private_input::<(#(#types),*)>
        },
        InputType::Custom => quote! {
            #custom_fn_name
        },
    };

    // Check that the target architecture is riscv32 if doing public/private input.
    let target_check = if !matches!(input_type, InputType::Custom) {
        quote! {
            #[cfg(not(target_arch = "riscv32"))]
            compile_error!("NexusVM public and private input interfaces are not available for native builds, use a custom handler instead. Ex: #[nexus_rt::custom_input((x,y,z), fizz)]");
        }
    } else {
        quote! {}
    };

    // Build the output token stream
    let expanded = {
        let error_msg = match input_type {
            InputType::Public => "Failed to read public input",
            InputType::Private => "Failed to read private input",
            InputType::Custom => "Failed to read input",
        };
        quote! {
            #target_check
            #(#attrs)*
            fn #fn_name(#input_sig) #output {
                let (#(#inputs),*):(#(#types),*) = #input_handler().unwrap_or_else(|e| {
                    panic!("{}: {:?}", #error_msg, e);
                });
                #block
            }
        }
    };

    TokenStream::from(expanded)
}
