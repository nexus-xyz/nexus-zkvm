use clap::{Parser, Subcommand};
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt};

pub mod command;

mod utils;

const LOG_TARGET: &str = "nexus-tools";

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
    #[cfg(feature = "dev")]
    #[clap(flatten)]
    Dev(command::dev::Command),

    #[clap(flatten)]
    Common(command::common::Command),
}

pub fn setup_logger() -> tracing::subscriber::DefaultGuard {
    // TODO: replace with `EnvFilter` using compiled configs.
    let filter = filter::Targets::new().with_target(LOG_TARGET, tracing::Level::DEBUG);
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
