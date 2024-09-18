use proc_macro::TokenStream;
use proc_macro2::Ident;
use proc_macro_crate::{crate_name, FoundCrate};
use std::fmt::Display;
extern crate proc_macro;
use crate::io::{handle_input, handle_output, InputType, OutputType};
use quote::{format_ident, quote, ToTokens};
use syn::{Error, ItemFn};

mod entry;
mod io;
mod profile;

// Get the full path to the nexus_rt crate.
pub(crate) fn get_nexus_rt_ident() -> Ident {
    match crate_name("nexus_rt") {
        Ok(FoundCrate::Name(name)) => format_ident!("{}", name),
        _ => format_ident!("nexus_rt"),
    }
}

// Convert an error message to a TokenStream.
fn stream_error<T: ToTokens, U: Display>(tokens: T, message: U) -> TokenStream {
    Error::new_spanned(tokens, message)
        .into_compile_error()
        .into()
}

#[proc_macro_attribute]
pub fn main(args: TokenStream, input1: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input1.clone().into();
    let ItemFn {
        attrs, sig, block, ..
    } = syn::parse2::<syn::ItemFn>(input.clone()).unwrap();

    // Get the full path to the nexus_rt crate.
    let nexus_rt = get_nexus_rt_ident();
    let main_attr = quote! {#[#nexus_rt::main]};

    // If there are other attributes, those will need to be processed first.
    if !attrs.is_empty() {
        return (quote! {
            #(#attrs)*
            #main_attr
            #sig {
                #block
            }
        })
        .into();
    }

    // If there are no inputs or outputs that need to be handled we can do the final checks in entry.
    if sig.inputs.is_empty() && matches!(sig.output, syn::ReturnType::Default) {
        // Check that the main function has desired properties.
        return entry::main(args.into(), input)
            .map(Into::into)
            .unwrap_or_else(|err| err.into_compile_error().into());
    }

    // Determine the leftover input variables names that need to be marked as private.
    let mut inputs = vec![];
    for arg in sig.inputs.iter() {
        if let syn::FnArg::Typed(a) = arg {
            if let syn::Pat::Ident(a) = &*a.pat {
                inputs.push(a.ident.clone());
            } else {
                // Let the compiler error down the line instead for better visibility.
                return input1;
            }
        } else {
            return stream_error(&sig, "Main function cannot take `self` as input.");
        }
    }

    // Check if there are leftover input variables that need to be cleaned up with private_input attribute.
    let private_input: Option<proc_macro2::TokenStream> = if !inputs.is_empty() {
        Some(quote! {#[#nexus_rt::private_input(#(#inputs),*)]})
    } else {
        None
    };

    // Check if there are leftover return types that need to be cleaned up with public_output attribute.
    let public_output: Option<proc_macro2::TokenStream> =
        if let syn::ReturnType::Type(_, _) = sig.output {
            Some(quote! {#[#nexus_rt::public_output]})
        } else {
            None
        };

    // Main attribute at end to do final checks.
    (quote! {
        #private_input
        #public_output
        #main_attr
        #sig {
            #block
        }
    })
    .into()
}

#[proc_macro_attribute]
pub fn public_input(_attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_input(_attr, item, InputType::Public)
}

#[proc_macro_attribute]
pub fn private_input(_attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_input(_attr, item, InputType::Private)
}

#[proc_macro_attribute]
pub fn custom_input(_attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_input(_attr, item, InputType::Custom)
}

#[proc_macro_attribute]
pub fn public_output(_attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_output(_attr, item, OutputType::Public)
}

#[proc_macro_attribute]
pub fn custom_output(_attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_output(_attr, item, OutputType::Custom)
}

#[proc_macro_attribute]
pub fn profile(_args: TokenStream, input: TokenStream) -> TokenStream {
    profile::profile(input.into()).into()
}
