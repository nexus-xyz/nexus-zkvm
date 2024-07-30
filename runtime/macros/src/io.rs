use proc_macro::TokenStream;

#[derive(PartialEq)]
pub enum Segments {
    PublicInput,
    PublicOutput,
    PublicLogging,
}

#[proc_macro_attribute]
pub fn read_segment(args: TokenStream, input: TokenStream) -> TokenStream {
    assert_eq!( , Segments::PublicInput);

    let module: ItemMod = syn::parse2(input)?;

    let inner: ItemMod = syn::parse2(quote! {
        #[doc(hidden)]
        mod __inner {
            static mut OFFSET: usize = 0;

            #[no_mangle]
            unsafe fn fetch_at_offset<'a>(exhaust: bool) -> (bool, &'a [u8]) {
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
    })?;

    assert!(module.content.is_some());
    module.content.1.push(inner);

    Ok(quote! {
        #module
    })
}
