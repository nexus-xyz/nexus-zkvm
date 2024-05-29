//! Utilities for parsing elf files.

use nexus_vm::elf::{
    abi::{PT_LOAD, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS},
    endian::LittleEndian,
    ElfBytes,
};
use nexus_vm::{
    init_vm, parse_elf_bytes,
    rv32::{parse::parse_inst, Inst, RV32},
    memory::Memory,
};

use crate::{convert, Error, LOG_TARGET, VM};

pub fn parse_elf<M: Memory>(bytes: &[u8]) -> Result<VM<M>, Error> {
    let elf = parse_elf_bytes(bytes)?;

    let vm = init_vm(&elf, bytes)?;
    // convert immediately for preprocessing
    let insts = parse_instructions(&elf, bytes)?
        .into_iter()
        .map(convert::inst)
        .collect();
    let mem_init = parse_raw_memory(&elf, bytes)?;

    Ok(VM { vm, insts, mem_init })
}

fn parse_raw_memory(elf: &ElfBytes<LittleEndian>, data: &[u8]) -> Result<Vec<(u64, u8)>, Error> {
    let mut mem_init = Vec::new();

    let load_phdrs = elf
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD);

    for p in load_phdrs {
        let s = p.p_offset as usize;
        let e = (p.p_offset + p.p_filesz) as usize;
        let bytes = &data[s..e];

        let addr = p.p_vaddr as u32;
        for (i, byte) in bytes.iter().enumerate() {
            let addr = addr + (i as u32);
            mem_init.push((addr as u64, *byte));
        }
    }
    Ok(mem_init)
}

fn parse_instructions(elf: &ElfBytes<LittleEndian>, data: &[u8]) -> Result<Vec<Inst>, Error> {
    let sections = elf.section_headers().unwrap().iter().filter(|s| {
        s.sh_type == SHT_PROGBITS
            && s.sh_flags & u64::from(SHF_ALLOC) != 0
            && s.sh_flags & u64::from(SHF_EXECINSTR) != 0
    });

    let mut insts = Vec::new();
    for section in sections {
        let s = section.sh_offset as usize;
        let e = (section.sh_offset + section.sh_size) as usize;
        let bytes = &data[s..e];

        assert_eq!(bytes.len() % 4, 0);

        for (i, word) in bytes.chunks(4).enumerate() {
            let addr = section.sh_addr + (i as u64 * 4);
            let inst = parse_inst(addr as u32, word).unwrap_or_else(|err| {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?addr,
                    error = ?err,
                    "Failed to pass the instruction",
                );
                Inst {
                    pc: addr as u32,
                    len: 4,
                    word: 0,
                    inst: RV32::UNIMP,
                }
            });

            // UNIMP instruction is OK as long as it's not executed.
            match inst.inst {
                RV32::ECALL { .. } | RV32::EBREAK { .. } => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?addr,
                        "Unsupported instruction",
                    );
                    return Err(Error::Unsupported(inst.inst));
                }
                _ => ()
            }

            insts.push(inst);
        }
    }
    Ok(insts)
}
