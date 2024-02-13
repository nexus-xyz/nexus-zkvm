use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

pub mod command;
pub mod utils;

#[cfg(feature = "dev")]
const LOG_TARGET: &str = "nexus-tools-dev";

#[derive(Debug, Parser)]
#[command(name = "cargo", bin_name = "cargo")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    Nexus {
        #[command(subcommand)]
        command: Command,
    },
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Helper commands for the development inside workspace.
    #[cfg(feature = "dev")]
    #[clap(flatten)]
    Dev(command::dev::Command),

    /// Cli commands for interaction with the prover interface and the network.
    #[clap(flatten)]
    Common(command::common::Command),
}

pub fn setup_logger() -> tracing::subscriber::DefaultGuard {
    #[cfg(feature = "dev")]
    let _: () = {
        let _ = dotenvy::from_path(nexus_config::constants::CONFIG_ENV_PATH);
    };

    let filter = if let Ok(filter) = EnvFilter::try_from_default_env() {
        let f = filter;
        println!("{f}");
        f.boxed()
    } else {
        Targets::new()
            .with_target("r1cs", LevelFilter::OFF)
            .with_default(LevelFilter::INFO)
            .boxed()
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                .pretty()
                .with_file(false)
                .with_line_number(false),
        )
        .with(filter)
        .set_default()
}
