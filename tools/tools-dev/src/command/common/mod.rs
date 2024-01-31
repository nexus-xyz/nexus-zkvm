use clap::Subcommand;

pub mod new;
pub mod prove;
pub mod request;
pub mod run;
pub mod verify;

pub use self::{
    new::NewArgs, prove::ProveArgs, request::RequestArgs, run::RunArgs, verify::VerifyArgs,
};

#[derive(Debug, Subcommand)]
pub enum Command {
    New(NewArgs),
    Run(RunArgs),
    Prove(ProveArgs),
    Request(RequestArgs),
    Verify(VerifyArgs),
}

#[cfg(feature = "dev")]
use crate::command::dev::common_impl as dev_impl;

pub(crate) fn handle_command(cmd: Command) -> anyhow::Result<()> {
    match cmd {
        Command::New(args) => new::handle_command(args),
        #[cfg(feature = "dev")]
        cmd => dev_impl::handle_command(cmd),

        #[cfg(not(feature = "dev"))]
        _ => unimplemented!(),
    }
}
