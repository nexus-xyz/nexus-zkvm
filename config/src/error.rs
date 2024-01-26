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
