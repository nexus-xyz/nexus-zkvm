//! Wrapper macro for deriving `serde::Deserialize`.
//!
//! Linux (shell) environment variables are only allowed to contain alphanumeric (ASCII-text format) symbols, and
//! an underscore (_). And because underscore is already used as a separator, no struct names are allowed to contain
//! it. For example, `http_url` should be renamed to `httpurl`. Lowercase-with-no-underscores isn't conventional;
//! therefore, this macro renames each field manually.
//!
//! The macro duplicates struct definition with added `rename` attributes and derives `serde::Deserialize`, voiding
//! initial macro-input.

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse_macro_input;

#[proc_macro_derive(Deserialize, attributes(serde))]
pub fn derive_deserialize(input: TokenStream) -> TokenStream {
    let mut derive_input = parse_macro_input!(input as syn::DeriveInput);

    // macros are expanded in order.
    let attrs: TokenStream = quote! {
        #[derive(serde::Deserialize)]
        #[::serde_wrapper::black_hole]
    }
    .into();
    let new_attrs = parse_macro_input!(attrs with syn::Attribute::parse_outer);
    let old_attrs = &derive_input.attrs[..];
    derive_input.attrs = [&new_attrs[..], old_attrs].concat();

    let struct_item = match &mut derive_input.data {
        syn::Data::Struct(item) => item,
        _ => {
            // only modify structs.
            return derive_input.to_token_stream().into();
        }
    };

    for field in struct_item.fields.iter_mut() {
        let rename_ident = match &field.ident {
            Some(ident) => ident.to_string().replace('_', "").to_lowercase(),
            None => {
                // Handle unnamed fields (tuple structs)
                continue;
            }
        };
        
        if !rename_ident.is_empty() {
            let rename_attr: TokenStream = quote! {
                #[serde(rename = #rename_ident)]
            }
            .into();
            let attr = parse_macro_input!(rename_attr with syn::Attribute::parse_outer);

            field.attrs.extend(attr);
        }
    }

    derive_input.to_token_stream().into()
}

/// Not public API, do not use.
#[doc(hidden)]
#[proc_macro_attribute]
pub fn black_hole(_: TokenStream, _: TokenStream) -> TokenStream {
    TokenStream::new()
}
