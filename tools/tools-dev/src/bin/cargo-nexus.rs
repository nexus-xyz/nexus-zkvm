use clap::Parser;
use nexus_tools_dev::{command, setup_logger, Cli};

fn main() -> anyhow::Result<()> {
    let _guard = setup_logger();

    let Cli::Nexus { command } = Cli::parse();
    command::handle_command(command)
}
