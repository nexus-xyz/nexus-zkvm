use std::num::NonZeroU8;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};

use super::utils::air_column_crate_include;

const SIZE_FN_IDENT: &str = "const_size";
const OFFSET_FN_IDENT: &str = "const_offset";

struct ParsedVariant {
    ident: syn::Ident,
    size: usize,
    mask_next_row: bool,
}

pub fn generate_impl(input: TokenStream, preprocessed: bool) -> syn::Result<TokenStream> {
    let input: syn::ItemEnum = syn::parse2(input)?;
    sanitize_attrs(&input)?;
    let enum_ident = &input.ident;

    let variants = collect_variants(&input)?;

    let all_variants = all_variants_impl(&variants);
    let const_size_impl = const_size_impl(&variants);
    let (offset, const_offset_impl) = const_offset_impl(&variants);
    let mask_next_row_impl = mask_next_row_impl(&variants);

    let crate_ident: TokenStream = air_column_crate_include();
    let preprocessed_impl = if preprocessed {
        preprocessed_impl(&input, &variants, &crate_ident, enum_ident)?
    } else {
        TokenStream::new()
    };

    let size_fn_ident = format_ident!("{SIZE_FN_IDENT}");
    let offset_fn_ident = format_ident!("{OFFSET_FN_IDENT}");
    let column_impl = quote! {
        impl #enum_ident {
            #const_size_impl

            #const_offset_impl
        }

        impl #crate_ident::AirColumn for #enum_ident {
            const COLUMNS_NUM: usize = #offset;
            const ALL_VARIANTS: &'static [Self] = #all_variants;

            fn size(self) -> usize {
                Self::#size_fn_ident(self)
            }
            fn offset(self) -> usize {
                Self::#offset_fn_ident(self)
            }
            fn mask_next_row(self) -> bool {
                #mask_next_row_impl
            }
        }
    };
    Ok(quote! {
        #column_impl

        #preprocessed_impl
    })
}

fn all_variants_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    quote! {
        &[#(Self::#ident_iter,)*]
    }
}

fn const_size_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let size_fn_ident = format_ident!("{SIZE_FN_IDENT}");
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let size_iter = parsed_variants.iter().map(|v| v.size);
    quote! {
        #[doc = "Returns the number of actual columns used by this variant."]
        pub const fn #size_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #size_iter, )*
            }
        }
    }
}

fn const_offset_impl(parsed_variants: &[ParsedVariant]) -> (usize, TokenStream) {
    let mut offset = 0usize;
    let offset_iter = parsed_variants.iter().map(|v| {
        let off = offset;
        offset += v.size;
        off
    });
    let offset_fn_ident = format_ident!("{OFFSET_FN_IDENT}");
    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let const_offset_impl = quote! {
        #[doc = "Returns the starting offset index for a variant."]
        pub const fn #offset_fn_ident(self) -> usize {
            match self {
                #( Self::#ident_iter => #offset_iter, )*
            }
        }
    };
    (offset, const_offset_impl)
}

fn preprocessed_impl(
    input: &syn::ItemEnum,
    parsed_variants: &[ParsedVariant],
    crate_ident: &TokenStream,
    enum_ident: &syn::Ident,
) -> Result<TokenStream, syn::Error> {
    // parse prefix
    let mut prefix = None;
    for attr in &input.attrs {
        if attr
            .path
            .get_ident()
            .is_none_or(|ident| *ident != "preprocessed_prefix")
        {
            continue;
        }
        let syn::Meta::NameValue(meta) = attr.parse_meta()? else {
            return Err(syn::Error::new_spanned(attr, "string literal is expected"));
        };
        if let syn::Lit::Str(s) = meta.lit {
            if prefix.is_none() {
                prefix = Some(s.value())
            } else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "repeating `preprocessed_prefix` attribute",
                ));
            }
        } else {
            return Err(syn::Error::new_spanned(attr, "string literal is expected"));
        }
    }

    let prefix = prefix.ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "preprocessed prefix attribute must be present",
        )
    })?;

    let ident_iter = parsed_variants.iter().map(|v| &v.ident);
    let size_iter = parsed_variants.iter().map(|v| v.size);
    let ids: Vec<String> = (ident_iter.clone())
        .zip(size_iter)
        .flat_map(|(ident, size)| {
            (0..size).map(|i| {
                let ident = ident.to_string().to_case(Case::Snake);
                format!("{prefix}_{ident}_{i}")
            })
        })
        .collect();
    Ok(quote! {
        impl #crate_ident::PreprocessedAirColumn for #enum_ident {
            const PREPROCESSED_IDS: &'static [&'static str] = &[#(#ids,)*];
        }
    })
}

fn mask_next_row_impl(parsed_variants: &[ParsedVariant]) -> TokenStream {
    let mut ident_iter = parsed_variants
        .iter()
        .filter_map(|v| v.mask_next_row.then_some(&v.ident));
    if let Some(first) = ident_iter.next() {
        quote! {
            matches!(
                self,
                Self::#first #(| Self::#ident_iter)*
            )
        }
    } else {
        quote! { false }
    }
}

fn collect_variants(input: &syn::ItemEnum) -> syn::Result<Vec<ParsedVariant>> {
    let mut result = Vec::with_capacity(input.variants.len());
    for variant in input.variants.iter() {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new_spanned(
                &variant.fields,
                "non-unit variants are disallowed",
            ));
        }

        let mut size = None;
        let mut mask_next_row = false;
        for attr in &variant.attrs {
            match attr.path.get_ident() {
                Some(ident) if *ident == "mask_next_row" => {
                    let syn::Meta::Path(_) = attr.parse_meta()? else {
                        return Err(syn::Error::new_spanned(attr, "invalid attribute"));
                    };
                    if mask_next_row {
                        return Err(syn::Error::new_spanned(
                            attr,
                            "repeating `mask_next_row` attribute",
                        ));
                    }
                    mask_next_row = true;
                    continue;
                }
                Some(ident) if *ident == "size" => {}
                Some(ident) if *ident == "preprocessed_prefix" => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "preprocessed prefix is only allowed on the enum definition level",
                    ));
                }
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
        result.push(ParsedVariant {
            ident: variant.ident.clone(),
            size: size.get() as usize,
            mask_next_row,
        });
    }
    Ok(result)
}

fn sanitize_attrs(input: &syn::ItemEnum) -> syn::Result<()> {
    for attr in &input.attrs {
        if attr
            .path
            .get_ident()
            .is_some_and(|ident| *ident == "size" || *ident == "mask_next_row")
        {
            return Err(syn::Error::new_spanned(attr, "invalid attribute"));
        }
    }

    Ok(())
}
