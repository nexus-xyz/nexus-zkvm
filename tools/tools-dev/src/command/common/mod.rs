use clap::Subcommand;

pub mod new;
pub mod prove;
pub mod public_params;
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
    /// Compute proof of program execution.
    Prove(ProveArgs),
    /// Request proof status from the network; download it if it's finished.
    Request(RequestArgs),
    /// Verify the proof.
    Verify(VerifyArgs),
    /// Nova public parameters management.
    #[clap(name = "pp")]
    PublicParams(public_params::PublicParamsArgs),
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
