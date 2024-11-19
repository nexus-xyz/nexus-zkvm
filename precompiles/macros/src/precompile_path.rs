use std::fmt::Display;

use quote::{quote, ToTokens};
use serde::{Deserialize, Serialize};
use syn::{
    parse::{Parse, ParseStream},
    Ident, Path, Token,
};

/// Similar to the usual concept of a path but with the restrictions and features needed for our
/// use-case. Our paths are always absolute, and the precompile implementation's parent must be
/// where the precompile module's `generate_instruction_caller!` macro is defined. The user may
/// optionally rename the precompile for use in their client code.
#[derive(Debug, Clone)]
pub(crate) struct PrecompilePath {
    pub(crate) path: Vec<Ident>,
    pub(crate) rename: Option<Ident>,
}

impl PrecompilePath {
    fn as_syn_path_impl(path: &[Ident]) -> Path {
        let path = path
            .iter()
            .map(|ident| ident.to_string())
            .collect::<Vec<_>>()
            .join("::");

        syn::parse_str(&format!("::{}", path)).unwrap()
    }

    pub(crate) fn as_syn_path(&self) -> Path {
        Self::as_syn_path_impl(&self.path)
    }

    pub(crate) fn prefix(&self) -> Path {
        let mut path = self.path.clone();
        path.pop().unwrap(); // Safety: path is guaranteed to have at least two elements.

        Self::as_syn_path_impl(&path)
    }
}

impl Parse for PrecompilePath {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut path = Vec::new();
        let rename = loop {
            if input.is_empty() {
                break None;
            }

            let _separator = input.parse::<Token![::]>()?;
            let ident = input.parse::<Ident>()?;

            path.push(ident);

            if input.parse::<Token![as]>().is_ok() {
                let ident = input.parse::<Ident>()?;
                if !input.is_empty() {
                    return Err(syn::Error::new(
                        input.span(),
                        "Unexpected tokens after precompile rename.",
                    ));
                }

                break Some(ident);
            }
        };

        if path.len() < 2 {
            return Err(syn::Error::new(
                input.span(),
                "Precompile path must have at least two elements \
                    (module name and implementing struct).",
            ));
        }

        Ok(Self { path, rename })
    }
}

impl ToTokens for PrecompilePath {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        for ident in &self.path {
            tokens.extend(quote! { ::#ident });
        }

        if let Some(rename) = self.rename.as_ref() {
            tokens.extend(quote! { as #rename });
        }
    }
}

impl Display for PrecompilePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self
            .path
            .iter()
            .map(|ident| ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let rename = self.rename.as_ref();

        write!(f, "::{}", path)?;

        if let Some(rename) = rename {
            write!(f, " as {}", rename)?;
        }

        Ok(())
    }
}

pub struct SerializablePath(pub(crate) Path);

impl Serialize for SerializablePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.0.to_token_stream().to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializablePath {
    fn deserialize<D>(deserializer: D) -> Result<SerializablePath, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;
        let path = syn::parse_str(&path).map_err(serde::de::Error::custom)?;

        Ok(Self(path))
    }
}

impl From<PrecompilePath> for SerializablePath {
    fn from(path: PrecompilePath) -> Self {
        Self(path.as_syn_path())
    }
}
