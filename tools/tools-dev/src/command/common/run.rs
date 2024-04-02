use clap::Args;

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print instruction trace.
    #[arg(short)]
    pub verbose: bool,

    /// Build artifacts with the specified profile. "release-unoptimized" is default.
    #[arg(long, default_value = "release-unoptimized")]
    pub profile: String,

    /// Name of the bin target to run.
    #[arg(long)]
    pub bin: Option<String>,
}
