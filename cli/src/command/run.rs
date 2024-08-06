use clap::Args;
use std::collections::HashSet;
use std::path::Path;

use crate::utils::{cargo, path_to_artifact};

const ALLOWED_FEATURES: [&str; 1] = ["cycles"];

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print instruction trace.
    #[arg(short)]
    pub verbose: bool,

    /// Build artifacts with the specified profile. "dev" is default.
    #[arg(long, default_value = "dev")]
    pub profile: String,

    /// Name of the bin target to run.
    #[arg(long)]
    pub bin: Option<String>,

    /// Build artifacts with the specific features. "cycles" is default.
    #[arg(
        long,
        default_value = "cycles",
        value_name = "FEATURES",
        use_value_delimiter = true
    )]
    pub features: Vec<String>,
}

pub fn handle_command(args: RunArgs) -> anyhow::Result<()> {
    let RunArgs { verbose, profile, bin, features } = args;

    run_vm(bin, verbose, &profile, features)
}

fn run_vm(
    bin: Option<String>,
    verbose: bool,
    profile: &str,
    features: Vec<String>,
) -> anyhow::Result<()> {
    let allowed_features: HashSet<_> = ALLOWED_FEATURES.iter().cloned().collect();

    // Build cargo arguments
    let mut cargo_args = vec![
        "build",
        "--target=riscv32i-unknown-none-elf",
        "--profile",
        profile,
    ];

    // Filter and add valid features
    let valid_features: Vec<&&str> = features
        .iter()
        .filter_map(|f| allowed_features.get(f.as_str()))
        .collect();

    if !valid_features.is_empty() {
        cargo_args.push("--features");
        for feature in valid_features {
            cargo_args.push(feature);
            cargo_args.push(",");
        }
        cargo_args.pop(); // Remove trailing comma
    }

    cargo(None, cargo_args)?;

    let path = path_to_artifact(bin, profile)?;

    run_vm_with_elf_file(&path, verbose)
}

pub fn run_vm_with_elf_file(path: &Path, verbose: bool) -> anyhow::Result<()> {
    let opts = nexus_core::nvm::VMOpts {
        k: 1,
        machine: None,
        file: Some(path.into()),
    };

    nexus_core::nvm::run_vm::<nexus_core::nvm::memory::Paged>(&opts, true, verbose)
        .map_err(Into::into)
}
