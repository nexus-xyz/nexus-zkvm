use proc_macro2::TokenStream;
use quote::quote;
use syn::Error;

use jolt_common::{attributes::Attributes, rv_trace::MemoryLayout};

fn parse_jolt_attributes() -> Result<Attributes, Error> {

    // HACK: We need to get the input path to the proc_macro builder.
    //       The "right" way to do this is to use a build script, but
    //       in our case it'll be user facing and might well confuse,
    //       especially as the user can want to write/use their own.
    //
    //       A better way to do this will be to use `--set-env` once
    //       it stabilizes, but for now by passing it through cfg we
    //       can parse it out of the CARGO_ENCODED_RUSTFLAGS env var
    //       and use it.

    let mark = "--cfgcompile_config_dir=";

    let rust_flags = std::env::var_os("CARGO_ENCODED_RUSTFLAGS").ok_or()?;
    let path_loc = rust_flags.find(mark).ok_or()?;
    let path = rust_flags[path_loc + mark.len()..].to_string();

    match fs::OpenOptions::new()
        .read(true)
        .open([path.clone(), String::from(".attr.in")].join("/"))
    {
        Ok(mut fp) => {
            let mut attr_bytes = Vec::new();
            fp.read_to_end(&mut attr_bytes).ok_or()?;

            let attr = postcard::from_bytes::<Attributes>(attr_bytes.as_slice()).ok_or()?;

            Ok(attr)
        },
        Err(e) => {
            return Err(e).map_err(BuildError::IOError);
        },
    }
}

pub fn setup() -> Result<TokenStream, Error> {

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let attributes = parse_jolt_attributes()?;
    let memory_layout =
        MemoryLayout::new(attributes.max_input_size, attributes.max_output_size);
    let input_start = memory_layout.input_start;
    let output_start = memory_layout.output_start;
    let max_input_len = attributes.max_input_size as usize;
    let max_output_len = attributes.max_output_size as usize;

    Ok(quote! {
        unsafe fn __nexus__fetch_at_offset<'a>(exhaust: bool) -> (bool, &'a [u8]) {
            static mut OFFSET: usize = 0;

            if OFFSET >= #max_input_len {
                return (false, &[]);
            }

            let input_ptr = (#input_start as *const u8).offset(OFFSET as isize);

            let mut input_slice;
            if exhaust {
                input_slice = core::slice::from_raw_parts(input_ptr, #max_input_len);
                OFFSET = #max_input_len;
            } else {
                input_slice = core::slice::from_raw_parts(input_ptr, 1);
                OFFSET += 1;
            }

            (true, input_slice)
        }

        pub fn read_compile_input<T: serde::de::DeserializeOwned>() -> Result<T, postcard::Error> {
            let mut ret;
            unsafe {
                ret = __nexus__fetch_at_offset(true);
            }

            match ret {
                (true, slice) => postcard::take_from_bytes::<T>(slice).map(|(v, _)| v),
                (false, slice) => Err(postcard::Error::DeserializeUnexpectedEnd),
            }
        }

        pub fn read_from_compile_input() -> Option<u8> {
            let mut ret;

            unsafe {
                ret = __nexus__fetch_at_offset(false);
            }

            match ret {
                (true, slice) => Some(slice[0]),
                (false, _) => None,
            }
        }
    })
}
