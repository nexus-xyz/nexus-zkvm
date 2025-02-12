//! # cargo-nexus
//!
//! Nexus zkVM command-line interface.
//!
//! ## Installation
//! In order to install, just run the following command
//!
//! ```sh
//! cargo install cargo-nexus
//! ```
//!
//! This will install cargo-nexus in your ~/.cargo/bin.<br>
//! Make sure to add ~/.cargo/bin directory to your PATH variable.
//!
//! ## Usage
//! The documentation is available at https://docs.nexus.xyz/.
//!
//! To see all the available commands, run
//! ```sh
//! cargo nexus --help
//! ```

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

pub fn setup_logger() -> tracing::subscriber::DefaultGuard {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env()
        .unwrap();

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

/// Default environment variables for legacy prover configuration.
const ENV: &str = r#"
NEXUS_VM_K=16
NEXUS_VM_PROVER=nova-seq
"#;
