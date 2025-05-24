pub mod cpu;
pub mod elf;
pub mod emulator;
pub mod error;
pub mod memory;
pub mod riscv;
pub mod system;
pub mod trace;

pub use crate::elf::WORD_SIZE;
pub use crate::system::SyscallCode;

#[cfg(test)]
macro_rules! read_testing_elf_from_path {
    ($path:expr) => {{
        if cfg!(target_arch = "wasm32") {
            crate::elf::ElfFile::from_bytes(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                $path
            )))
            .ok()
            .unwrap()
        } else {
            crate::elf::ElfFile::from_path(concat!(env!("CARGO_MANIFEST_DIR"), $path))
                .ok()
                .expect("Unable to load ELF file")
        }
    }};
}

#[cfg(test)]
pub(crate) use read_testing_elf_from_path;

#[cfg(test)]
macro_rules! read_testing_binary_from_path {
    ($path:expr) => {{
        if cfg!(target_arch = "wasm32") {
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), $path)).to_vec()
        } else {
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), $path)).unwrap()
        }
    }};
}

#[cfg(test)]
pub(crate) use read_testing_binary_from_path;
