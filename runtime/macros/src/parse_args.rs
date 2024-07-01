use proc_macro2::Span;
use proc_macro2::TokenStream;
use syn::parse::{Parse, ParseStream};

const MEMORY_LIMIT_IDENT: &str = "memlimit";

struct MemLimit(i32);

impl Parse for MemLimit {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let input: syn::Meta = input.parse()?;

        if let syn::Meta::NameValue(meta) = input {
            meta.path
                .get_ident()
                .filter(|ident| *ident == MEMORY_LIMIT_IDENT)
                .ok_or(syn::Error::new(
                    Span::call_site(),
                    format!("`{}` parameter is expected", MEMORY_LIMIT_IDENT),
                ))?;
            if let syn::Lit::Int(i) = meta.lit {
                let value = i.base10_parse::<u16>()?;
                Ok(Self(i32::from(value).saturating_mul(0x100000)))
            } else {
                Err(syn::Error::new(
                    Span::call_site(),
                    "memory limit should be an integer",
                ))
            }
        } else {
            Err(syn::Error::new(Span::call_site(), "unexpected macro input"))
        }
    }
}

/// Parse memory limit from macro arguments.
pub fn parse_memory_limit(args: TokenStream) -> syn::Result<i32> {
    if args.is_empty() {
        Ok(-1)
    } else {
        syn::parse::<MemLimit>(args.into()).map(|m| m.0)
    }
}
