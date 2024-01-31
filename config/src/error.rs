use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Config(config::ConfigError),
    DotEnv(dotenvy::Error),
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Self::Config(err)
    }
}

impl From<dotenvy::Error> for Error {
    fn from(err: dotenvy::Error) -> Self {
        Self::DotEnv(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(err) => write!(f, "{err}"),
            Error::DotEnv(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}
