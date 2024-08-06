use proc_macro::TokenStream;

use jolt_common::{attributes::Attributes, rv_trace::MemoryLayout};

type NexusJoltAttributes = (u32, Attributes);

fn parse_jolt_attributes() -> Result<NexusJoltAttributes, Error> {

    let re = Regex::new(r#"compile_config_dir="(?<path>[^"]*)"#).unwrap();
    let sta = std::env::var_os("CARGO_ENCODED_RUSTFLAGS").unwrap();
    let stb = sta.as_os_str().to_str().unwrap();

    eprintln!("{}", stb);
    let cp = re.captures(stb).unwrap();

    let path = cp.name("path").unwrap().as_str();

    match std::fs::OpenOptions::new()
        .read(true)
        .open(path)
    {
        Ok(mut fp) => {
            let mut attr_bytes = Vec::new();
            fp.read_to_end(&mut attr_bytes).unwrap();//.ok_or()?;

            let attr = postcard::from_bytes::<NexusJoltAttributes>(attr_bytes.as_slice()).unwrap();//ok_or()?;

            Ok(attr)
        },
        Err(e) => {
            panic!("foo")
            //return Err(e).map_err(BuildError::IOError);
        },
    }
}

#[derive(PartialEq)]
pub enum Segments {
    PublicInput,
    PublicOutput,
    PublicLogging,
}

#[proc_macro_attribute]
pub fn read_segment(args: TokenStream, input: TokenStream) -> TokenStream {
    assert_eq!(args, Segments::PublicInput);

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let (max_log_size, attributes) = parse_jolt_attributes()?;
    let memory_layout =
        MemoryLayout::new(attributes.max_input_size, attributes.max_output_size + max_log_size);
    let segment_start = memory_layout.input_start;
    let max_segment_len = attributes.max_input_size as usize;

    let module: ItemMod = syn::parse2(input)?;

    let inner: ItemMod = syn::parse2(quote! {
        #[doc(hidden)]
        mod __inner {
            static mut OFFSET: usize = 0;

            #[no_mangle]
            unsafe fn fetch_at_offset<'a>(exhaust: bool) -> Result<&'a [u8], Error> {
                if OFFSET >= #max_segment_len {
                    return (false, &[]);
                }

                let segment_ptr = (#segment_start as *const u8).bytes_offset(OFFSET as isize);

                let mut segment_slice;
                if exhaust {
                    segment_slice = core::slice::from_raw_parts(segment_ptr, #max_segment_len);
                    OFFSET = #max_segment_len;
                } else {
                    segment_slice = core::slice::from_raw_parts(segment_ptr, 1);
                    OFFSET += 1;
                }

                (true, segment_slice)
            }
        }
    })?;

    assert!(module.content.is_some());
    module.content.1.push(inner);

    Ok(quote! {
        #module
    })
}

#[proc_macro_attribute]
pub fn write_segment(args: TokenStream, input: TokenStream) -> TokenStream {

    // see: https://github.com/a16z/jolt/blob/main/jolt-sdk/macros/src/lib.rs#L276
    let (max_log_size, attributes) = parse_jolt_attributes()?;
    let memory_layout =
        MemoryLayout::new(attributes.max_input_size, attributes.max_output_size + max_log_size);

    let (segment_start, max_segment_len) = match args {
        Segments::PublicOutput => (memory_layout.output_start, attributes.max_output_size),
        Segments::PublicLogging => (attributes.max_output_size, attributes.max_output_size + max_log_size),
        _ => panic!("unknown write segment")
    }

    let module: ItemMod = syn::parse2(input)?;

    let inner: ItemMod = syn::parse2(quote! {
        #[doc(hidden)]
        mod __inner {
            static mut OFFSET: usize = 0;

            #[no_mangle]
            unsafe fn set_at_offset(bytes: &[u8]) -> Result<(), Error> {
                if OFFSET + bytes.len() >= #max_segment_len {

                }

                let segment_ptr = (#segment_start as *const u8).bytes_offset(OFFSET as isize);
                segment_ptr.write_bytes(bytes, bytes.len());
                OFFSET += bytes.len();

                Ok()
            }
        }
    })?;

    assert!(module.content.is_some());
    module.content.1.push(inner);

    Ok(quote! {
        #module
    })
}
