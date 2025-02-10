use std::num::NonZeroU8;

use convert_case::{Case, Casing};
use proc_macro2::TokenStream;
use quote::quote;

const TOTAL_COLS_IDENT: &str = "COLUMNS_NUM";
const STRING_IDS_IDENT: &str = "STRING_IDS";
const ALL_VARIANTS_IDENT: &str = "ALL_VARIANTS";

const SIZE_FN_IDENT: &str = "size";
const OFFSET_FN_IDENT: &str = "offset";

pub fn generate_impls(input: TokenStream) -> syn::Result<TokenStream> {
    let input: syn::ItemEnum = syn::parse2(input)?;

    let enum_ident = &input.ident;
    let with_ids = parse_attrs(&input)?;
    let variants = collect_variants(&input)?;

    let _ident_iter = variants.iter().map(|v| &v.0);

    let ident_iter = _ident_iter.clone();
    let size_iter = variants.iter().map(|v| usize::from(v.1));

    let all_variants_impl = {
        let ident_iter = ident_iter.clone();
        let const_ident = quote::format_ident!("{ALL_VARIANTS_IDENT}");
        quote! {
            pub const #const_ident: &[#enum_ident] = &[#(Self::#ident_iter,)*];
        }
    };
    let string_id_impl = if with_ids {
        let ids: Vec<String> = (ident_iter.clone())
            .zip(size_iter.clone())
            .flat_map(|(ident, size)| {
                (0..size).map(|i| {
                    let ident = ident.to_string().to_case(Case::Snake);
                    format!("{ident}_{i}")
                })
            })
            .collect();
        let const_ident = quote::format_ident!("{STRING_IDS_IDENT}");
        quote! {
            pub const #const_ident: &[&str] = &[#(#ids,)*];
        }
    } else {
        TokenStream::new()
    };

    let size_fn_ident = quote::format_ident!("{SIZE_FN_IDENT}");
    let size_impl = quote! {
        #[doc = "Returns the number of actual columns used by this variant."]
        pub const fn #size_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #size_iter, )*
            }
        }
    };

    let ident_iter = _ident_iter;
    let mut offset = 0usize;
    let offset_iter = variants.iter().map(|v| {
        let off = offset;
        offset += usize::from(v.1);
        off
    });
    let offset_fn_ident = quote::format_ident!("{OFFSET_FN_IDENT}");
    let offset_impl = quote! {
        #[doc = "Returns the starting offset index for a variant."]
        pub const fn #offset_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #offset_iter, )*
            }
        }
    };

    let total_cols_ident = quote::format_ident!("{TOTAL_COLS_IDENT}");
    Ok(quote! {
        impl #enum_ident {
            #[doc = "Constant sum of all variants sizes."]
            pub const #total_cols_ident: usize = #offset;

            #size_impl

            #offset_impl

            #all_variants_impl

            #string_id_impl
        }
    })
}

fn collect_variants(input: &syn::ItemEnum) -> syn::Result<Vec<(syn::Ident, u8)>> {
    let mut result = Vec::with_capacity(input.variants.len());
    for variant in input.variants.iter() {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &variant.fields,
                "non-unit variants are disallowed",
            ));
        }

        let mut size = None;
        for attr in &variant.attrs {
            match attr.path.get_ident() {
                Some(ident) if *ident == "column_derive" => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "`column_derive` attribute cannot be used on a variant",
                    ));
                }
                Some(ident) if *ident == "size" => {}
                _ => continue,
            }

            let syn::Meta::NameValue(meta) = attr.parse_meta()? else {
                return Err(syn::Error::new_spanned(attr, "integer value expected"));
            };
            if let syn::Lit::Int(i) = meta.lit {
                let value = i.base10_parse::<NonZeroU8>()?;
                if size.is_none() {
                    size = Some(value)
                } else {
                    return Err(syn::Error::new_spanned(attr, "repeating `size` attribute"));
                }
            } else {
                return Err(syn::Error::new_spanned(attr, "integer value expected"));
            }
        }
        let Some(size) = size else {
            return Err(syn::Error::new_spanned(
                variant,
                "size attribute must be present",
            ));
        };
        result.push((variant.ident.clone(), size.get()));
    }
    Ok(result)
}

/// Returns `true` if the macro should also generate static array of preprocessed ids.
fn parse_attrs(input: &syn::ItemEnum) -> syn::Result<bool> {
    let mut flag = false;
    for attr in &input.attrs {
        if attr
            .path
            .get_ident()
            .is_none_or(|ident| *ident != "column_derive")
        {
            continue;
        }
        let ident: syn::Ident = attr.parse_args()?;
        if ident != "string_id" {
            return Err(syn::Error::new_spanned(attr, "unsupported attribute"));
        }
        if flag {
            return Err(syn::Error::new_spanned(
                attr,
                "repeating `string_id` attribute",
            ));
        }
        flag = true;
    }
    Ok(flag)
}
