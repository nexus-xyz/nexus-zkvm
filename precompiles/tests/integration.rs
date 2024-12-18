#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nexus_vm::elf::ElfFile;

    #[test]
    fn test() {
        let path_to_elf =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/program_with_dummy_div");

        let elf = ElfFile::from_path(path_to_elf.as_os_str().to_str().unwrap()).unwrap();

        assert!(!elf.nexus_metadata.is_empty());
    }
}
