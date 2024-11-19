use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{spanned::Spanned, Ident};

use crate::precompile_path::{PrecompilePath, SerializablePath};

/// Generate the custom RISC-V instruction implementations for each precompile. Separated for
/// readability.
pub(crate) fn generate_instruction_impls(paths: &[PrecompilePath]) -> TokenStream {
    let num_precompiles = paths.len() as u16;

    (0..num_precompiles)
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
            let path = &path.as_syn_path();
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
        .collect()
}

/// Generate the static variables that hold the precompile metadata.
#[cfg(target_arch = "riscv32")]
pub(crate) fn generate_statics(paths: &Vec<PrecompilePath>) -> Result<TokenStream, syn::Error> {
    let num_precompiles = paths.len() as u16;
    let mut statics = quote! {
        #[no_mangle]
        #[link_section = ".note.nexus-precompiles"]
        pub static PRECOMPILE_COUNT: u16 = #num_precompiles;
    };

    for (i, path) in (0..num_precompiles).zip(paths) {
        let symbol_name = Ident::new(&format!("PRECOMPILE_{i}"), Span::call_site());
        let serializable_path = SerializablePath::from((*path).clone());
        let data = serde_json::to_string(&serializable_path);

        if let Err(e) = data {
            return Err(syn::Error::new(
                path.as_syn_path().span(),
                format!("Failed to serialize metadata for {}", e),
            ));
        }

        let data = data.unwrap();
        statics.extend(quote! {
            #[no_mangle]
            #[link_section = ".note.nexus-precompiles"]
            pub static #symbol_name: &'static str = #data;
        });
    }

    Ok(statics)
}
