use clap::Args;

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Program hash.
    pub hash: String,
}
