use proc_macro2::TokenStream;
use quote::quote;
use syn::Error;

use jolt_common::rv_trace::MemoryLayout;

pub fn setup() -> Result<TokenStream, Error> {

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let attributes = parse_jolt_attributes();
    let memory_layout =
        MemoryLayout::new(attributes.max_input_size, attributes.max_output_size);
    let input_start = memory_layout.input_start;
    let output_start = memory_layout.output_start;
    let max_input_len = attributes.max_input_size as usize;
    let max_output_len = attributes.max_output_size as usize;

    Ok(quote! {
        fn __nexus__fetch_at_offset<'a>(exhaust: bool) -> &'a Option<[u8]> {
            static mut OFFSET: usize = 0;

            if OFFSET >= max_input_len {
                return None;
            }

            let input_ptr = (#input_start as *const u8).offset(OFFSET);

            let mut input_slice;
            if exhaust {
                unsafe {
                    input_slice = core::slice::from_raw_parts(input_ptr, #max_input_len);
                    OFFSET = #max_input_len;
                }
            } else {
                unsafe {
                    input_slice = core::slice::from_raw_parts(input_ptr, 1);
                    OFFSET += 1;
                }
            }

            Some(input_slice)
        }

        pub fn read_compile_input<T: DeserializeOwned>() -> Result<T, postcard::Error> {
            if let Some(slice) = __nexus__fetch_at_offset(true) {
                postcard::take_from_bytes::<T>(slice)
            }

            Err(postcard::Error::DeserializeUnexpectedEnd)
        }

        pub fn read_from_compile_input() -> Option<u8> {
            __nexus__fetch_at_offset(false).map(|s| s[0])
        }
    })
}
