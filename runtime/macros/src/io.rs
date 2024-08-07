use proc_macro2::TokenStream;
use quote::quote;
use std::io::Read;
use syn::{Error, ItemMod};

use regex::Regex;

use jolt_common::{attributes::Attributes, rv_trace::MemoryLayout};

// second entry is max_log_size
type ExtAttributes = (Attributes, u64);

fn parse_jolt_attributes(input: &TokenStream) -> Result<ExtAttributes, Error> {
    let err = Error::new_spanned(input, "unable to find or parse jolt io configuration");

    let regex = Regex::new(r#"compile_config_dir="(?<path>[^"]*)"#).map_err(|_| err.clone())?;

    let raw_flags = std::env::var_os("CARGO_ENCODED_RUSTFLAGS").ok_or_else(|| err.clone())?;
    let flags = raw_flags.as_os_str().to_str().ok_or_else(|| err.clone())?;

    let capture = regex.captures(flags).ok_or_else(|| err.clone())?;
    let path = capture.name("path").ok_or_else(|| err.clone())?;

    match std::fs::OpenOptions::new().read(true).open(path.as_str()) {
        Ok(mut fp) => {
            let mut attr_bytes = Vec::new();
            fp.read_to_end(&mut attr_bytes).map_err(|_| err.clone())?;

            let attr = postcard::from_bytes::<ExtAttributes>(attr_bytes.as_slice())
                .map_err(|_| err.clone())?;

            Ok(attr)
        }
        Err(_) => {
            return Err(err);
        }
    }
}

pub fn read_segment(args: TokenStream, input: TokenStream) -> Result<TokenStream, Error> {
    // todo: would be nice to replace this with an enum, but limited by export limitations of `proc-macro` crate types
    assert_eq!(&args.to_string(), "PublicInput");

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let (attributes, max_log_size) = parse_jolt_attributes(&input)?;
    let memory_layout = MemoryLayout::new(
        attributes.max_input_size,
        attributes.max_output_size + max_log_size,
    );
    let segment_start = memory_layout.input_start;
    let max_segment_len = attributes.max_input_size as usize;

    let mut module: ItemMod = syn::parse2(input.clone())?;

    let inner: TokenStream = syn::parse2(quote! {
        #[doc(hidden)]
        mod __inner {
            extern crate alloc;
            static mut OFFSET: usize = 0;

            pub unsafe fn fetch_at_offset(exhaust: bool) -> Option<alloc::vec::Vec<u8>> {
                if OFFSET >= #max_segment_len {
                    return None;
                }

                let segment_ptr = (#segment_start as *const u8).byte_offset(OFFSET as isize);

                let mut segment_slice;
                if exhaust {
                    segment_slice = core::slice::from_raw_parts(segment_ptr, #max_segment_len);
                    OFFSET = #max_segment_len;
                } else {
                    segment_slice = core::slice::from_raw_parts(segment_ptr, 1);
                    OFFSET += 1;
                }

                Some(segment_slice.to_vec())
            }
        }
    })?;

    if let Some((_, entries)) = &mut module.content {
        entries.push(syn::Item::Verbatim(inner));
    } else {
        return Err(Error::new_spanned(&input, "unable to extend empty module"));
    }

    Ok(quote! {
        #module
    })
}

pub fn write_segment(args: TokenStream, input: TokenStream) -> Result<TokenStream, Error> {
    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let (attributes, max_log_size) = parse_jolt_attributes(&input)?;
    let memory_layout = MemoryLayout::new(
        attributes.max_input_size,
        attributes.max_output_size + max_log_size,
    );

    // todo: would be nice to replace these with an enum, but limited by export limitations of `proc-macro` crate types
    let (segment_start, max_segment_len) = match args.to_string().as_str() {
        "PublicOutput" => (
            memory_layout.output_start,
            attributes.max_output_size as usize,
        ),
        "PublicLogging" => (
            attributes.max_output_size,
            (attributes.max_output_size + max_log_size) as usize,
        ),
        _ => panic!("unknown write segment"),
    };

    let mut module: ItemMod = syn::parse2(input.clone())?;

    let inner: TokenStream = syn::parse2(quote! {
        #[doc(hidden)]
        mod __inner {
            static mut OFFSET: usize = 0;

            pub unsafe fn set_at_offset(bytes: &[u8]) -> bool {
                if OFFSET + bytes.len() >= #max_segment_len {
                    return false;
                }

                let segment_ptr = (#segment_start as *mut u8).byte_offset(OFFSET as isize);
                core::ptr::copy(bytes.as_ptr(), segment_ptr, bytes.len());
                OFFSET += bytes.len();

                true
            }
        }
    })?;

    if let Some((_, entries)) = &mut module.content {
        entries.push(syn::Item::Verbatim(inner));
    } else {
        return Err(Error::new_spanned(&input, "unable to extend empty module"));
    }

    Ok(quote! {
        #module
    })
}
