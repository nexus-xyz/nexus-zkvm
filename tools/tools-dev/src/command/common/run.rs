use clap::Args;

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print instruction trace.
    #[arg(short)]
    pub verbose: bool,

    /// Build artifacts with the release profile. Equivalent to "--profile release".
    #[arg(short, name = "r", conflicts_with = "profile")]
    pub release: bool,

    /// Build artifacts with the specified profile. "dev" is default.
    #[arg(long, default_value = "dev")]
    pub profile: String,

    /// Name of the bin target to run.
    #[arg(long)]
    pub bin: Option<String>,
}
