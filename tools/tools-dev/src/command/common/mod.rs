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
    /// Create a new Nexus package at <path>.
    New(NewArgs),
    /// Run a binary with the Nexus VM.
    Run(RunArgs),
    /// Send compiled binary to the Nexus prover network.
    Prove(ProveArgs),
    /// Request proof status; download it if it's finished.
    Request(RequestArgs),
    /// Verify the proof.
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
