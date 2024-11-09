use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Ident, Path, Token,
};

pub(crate) struct PathWithRename {
    pub(crate) path: Path,
    pub(crate) rename: Option<Ident>,
}

impl Parse for PathWithRename {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path = input.parse()?;

        let rename = if input.peek(Token![as]) {
            input.parse::<Token![as]>()?;
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Self { path, rename })
    }
}

impl ToTokens for PathWithRename {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let path = &self.path;
        let rename = self.rename.as_ref();

        tokens.extend(quote! { #path });

        if let Some(rename) = rename {
            tokens.extend(quote! { as #rename });
        }
    }
}
