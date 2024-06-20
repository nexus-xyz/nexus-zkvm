use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod command;

mod utils;

#[derive(Debug, Parser)]
#[command(name = "cargo", bin_name = "cargo")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    Nexus {
        #[command(subcommand)]
        command: command::Command,
    },
}

const LOG_TARGET: &str = "nexus-tools";

pub fn setup_logger() -> tracing::subscriber::DefaultGuard {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env()
        .unwrap()
        .add_directive("r1cs=off".parse().unwrap());

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

/// Default environment variables for prover configuration.
const ENV: &str = r#"
NEXUS_VM_K=16
NEXUS_VM_PROVER=nova-seq
"#;
