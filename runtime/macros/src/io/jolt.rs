use proc_macro2::TokenStream;
use quote::quote;
use syn::Error;

use jolt_common::{attributes::Attributes, rv_trace::MemoryLayout};

fn parse_jolt_attributes() -> Result<(String, Attributes), Error> {

    println!("{:?}", std::env::var_os("CARGO_TARGET_DIR"));

    let memory_size = jolt_common::constants::DEFAULT_MEMORY_SIZE;
    let stack_size = jolt_common::constants::DEFAULT_STACK_SIZE;
    let max_input_size = jolt_common::constants::DEFAULT_MAX_INPUT_SIZE;
    let max_output_size = jolt_common::constants::DEFAULT_MAX_OUTPUT_SIZE;

    Ok((String::from(""),
        Attributes {
            wasm: false,
            memory_size,
            stack_size,
            max_input_size,
            max_output_size,
        })
    )
}

pub fn setup() -> Result<TokenStream, Error> {

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let (_, attributes) = parse_jolt_attributes()?;
    let memory_layout =
        MemoryLayout::new(attributes.max_input_size, attributes.max_output_size);
    let input_start = memory_layout.input_start;
    let output_start = memory_layout.output_start;
    let max_input_len = attributes.max_input_size as usize;
    let max_output_len = attributes.max_output_size as usize;

    Ok(quote! {
        fn __nexus__fetch_at_offset<'a>(exhaust: bool) -> (bool, &'a [u8]) {
            unsafe {
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
