extern crate proc_macro;

mod path_with_rename;

use path_with_rename::PathWithRename;
use proc_macro::TokenStream;
use quote::quote;
use quote::ToTokens;
use std::fmt::Display;
use syn::{parse::Parser, punctuated::Punctuated, Error, Token};

// Convert an error message to a TokenStream.
fn spanned_error<T: ToTokens, U: Display>(tokens: T, message: U) -> TokenStream {
    Error::new_spanned(tokens, message)
        .into_compile_error()
        .into()
}

/// Usage:
///
/// ```rust,ignore
/// use_precompiles!(precompile_module::Precompile as Mine, another_module::Precompile as Theirs);
/// ```
///
/// Each listed precompile must be listed using its complete path, starting with the module name.
/// If needed, the `as` keyword can be used to rename the precompile for use in the client code.
///
/// Internally, this macro generates custom RISC-V instructions for each precompile and defines a
/// set of custom traits and implementations that allow the precompiles to be called naturally while
/// remaining unambiguously interpretable by the VM.
#[proc_macro]
pub fn use_precompiles(input: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let mut output = proc_macro2::TokenStream::new();

    // 1. Parse the input into a list of paths to precompile implementations.
    let paths =
        match Punctuated::<PathWithRename, Token![,]>::parse_terminated.parse2(input.clone()) {
            Ok(p) => p.into_iter().collect::<Vec<PathWithRename>>(),
            Err(e) => {
                return e.into_compile_error().into();
            }
        };

    // We reserve 256 precompile codes for potential internal uses. 768 should still be more
    // than enough for any reasonable guest program, for now. This number MUST be <= 1024 due to
    // the 10-bit encoding of the precompile index in the custom RISC-V instruction.
    const MAX_PRECOMPILES: usize = 768;

    if paths.is_empty() {
        return spanned_error(input, "Must specify at least one precompile.");
    } else if paths.len() > MAX_PRECOMPILES {
        return spanned_error(
            input,
            format!("Cannot use more than {MAX_PRECOMPILES} precompiles in one guest program."),
        );
    }

    // 2. Import each precompile for the client's later use.
    let imports = paths.iter().map(|path| {
        quote! {
            use #path;
        }
    });
    output.extend(imports);

    // 3. For each path, check that it is a valid precompile at compile time.
    let valid_checks: Vec<proc_macro2::TokenStream> = paths
        .iter()
        .map(|path| {
            let path = &path.path;
            quote! { is_valid::<#path>() }
        })
        .collect();

    // The strange syntax here serves to create an anonymous namespace that doesn't pollute the
    // global namespace with the `is_valid` function.
    let check_output = quote! {
        const _: () = {
            // This function will not compile if T does not implement the required traits.
            const fn is_valid<T: ::nexus_precompiles::PrecompileInstruction>() {}

            #(#valid_checks)*
        };
    };
    output.extend(check_output);

    // 4. Define the trait that will emit the instruction for each precompile.
    let emitter_trait = quote! {
        pub trait InstructionEmitter {
            fn emit_instruction(rs1: u32, rs2: u32, imm: u32) -> u32;
        }
    };
    output.extend(emitter_trait);

    // 5. Generate code that picks a 10-bit index 0-1023 for each precompile and uses it to generate
    // a custom RISC-V instruction for each precompile. This is done by encoding the precompile
    // index into the `func3` and `func7` fields of the custom RISC-V instruction we use.

    // Safety: size already checked to be <= MAX_PRECOMPILES, guaranteed to fit in 10 bits
    let num_precompiles = paths.len() as u16;
    let insn_impls: proc_macro2::TokenStream = (0..num_precompiles)
        .zip(paths.iter())
        .map(|(i, path)| {
            // Format is index = 0b0000_00[fn7][fn3]
            const FN7_MASK: u16 = 0b011_1111_1000;
            const FN3_MASK: u16 = 0b0111;
            const R_TYPE_PRECOMPILE_OPCODE: u8 = 0b0001011;

            let fn7 = ((FN7_MASK & i) >> 3) as u8;
            let fn3 = (FN3_MASK & i) as u8;

            // ".insn ins_type opcode, func3, func7, rd, rs1, rs2"
            let insn = format!(
                ".insn r 0x{R_TYPE_PRECOMPILE_OPCODE:x}, 0x{fn3:x}, 0x{fn7:x}, {{rd}}, {{rs1}}, {{rs2}}"
            );
            let path = &path.path;
            quote! {
                impl InstructionEmitter for #path {
                    #[inline(always)]
                    fn emit_instruction(rs1: u32, rs2: u32, imm: u32) -> u32 {
                        #[cfg(target_arch = "riscv32")] {
                            let mut rd: u32;
                            unsafe {
                                ::core::arch::asm!(
                                    #insn,
                                    rd = out(reg) rd,
                                    rs1 = in(reg) rs1,
                                    rs2 = in(reg) rs2,
                                );
                            }
                            return rd;
                        }
                        #[cfg(not(target_arch = "riscv32"))] {
                            return <#path as ::nexus_precompiles::PrecompileInstruction>::native_call(rs1, rs2);
                        }
                    }
                }
            }
        })
        .collect();
    output.extend(insn_impls);

    // 6. Generate a `#[no_mangle]` static variable that expresses the number of precompiles present
    // in the guest binary. This is not likely super useful but serves as a guard against this macro
    // being called more than once globally (redefining a static symbol is a compiler error). In a
    // future update, this will be omitted and replaced by embedding the precompile metadata in the
    // binary itself.
    #[cfg(target_arch = "riscv32")]
    let macro_guard = quote! {
        #[no_mangle]
        #[link_section = ".nexus_precompile_count"]
        pub static PRECOMPILE_COUNT: u16 = #num_precompiles;
    };

    #[cfg(target_arch = "riscv32")]
    output.extend(macro_guard);

    // 7. Call each precompile's call-generating macro. This macro is expected to define and
    // implement a trait which is used for the actual precompile call. This should have the name
    // and interface that the user actually calls, for example,
    // `MyHash::hash(data: &[u8]) -> [u8; 32]`. The precompile's implementer is responsible for
    // ensuring that the generated code is correct and safe.

    let custom_generators = paths
        .iter()
        .map(|path| {
            let mut prefix = path.path.clone();

            // Remove the name of the precompile struct to get the path to its module.
            let _postfix = match prefix.segments.pop() {
                Some(segment) => segment,
                None => return Err(spanned_error(path, "Invalid path: no module specified")),
            };

            let path = &path.path;
            Ok(quote! {
                #prefix generate_instruction_caller!(#path);
            })
        })
        .collect::<Result<Vec<proc_macro2::TokenStream>, TokenStream>>();

    if let Err(e) = custom_generators {
        return e;
    }

    output.extend(custom_generators.unwrap());

    output.into()
}
