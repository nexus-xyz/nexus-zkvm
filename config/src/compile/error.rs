use std::io;

use toml::de;

#[derive(Debug)]
pub enum CompileError {
    Io(io::Error),
    Toml(de::Error),
}

impl From<io::Error> for CompileError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<de::Error> for CompileError {
    fn from(err: de::Error) -> Self {
        Self::Toml(err)
    }
}
