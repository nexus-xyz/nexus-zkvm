use clap::Args;

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(short)]
    pub verbose: bool,

    #[arg(short, long)]
    pub release: bool,

    #[arg(long)]
    pub bin: Option<String>,
}
