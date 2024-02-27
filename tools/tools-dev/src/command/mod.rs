#[cfg(feature = "dev")]
pub mod dev;

pub mod common;

use super::Command;

pub fn handle_command(cmd: Command) -> anyhow::Result<()> {
    match cmd {
        #[cfg(feature = "dev")]
        Command::Dev(cmd) => dev::handle_command(cmd),
        Command::Common(cmd) => common::handle_command(cmd),
    }
}
