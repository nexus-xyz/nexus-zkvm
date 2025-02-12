mod error;
mod loader;
mod parser;

pub use error::ParserError as ElfError;
pub use loader::ElfFile;
pub use nexus_common::constants::WORD_SIZE;
