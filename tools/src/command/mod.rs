use nexus_tools_dev::{Command, command::common::Command as CommonCommand};
use nexus_config::vm as vm_config;

pub mod new;
pub mod run;
pub mod prove;
pub mod request;
pub mod verify;
pub mod public_params;

// TODO: handle default values.
const DEFAULT_K: usize = 1;
const DEFAULT_NOVA_IMPL: vm_config::NovaImpl = vm_config::NovaImpl::Parallel;

pub fn handle_command(cmd: Command) -> anyhow::Result<()> {
    #![allow(irrefutable_let_patterns)] // rust-analyzer may give a false warning in a workspace.

    let Command::Common(cmd) = cmd else {
        unreachable!()
    };
    match cmd {
        CommonCommand::New(args) => new::handle_command(args),
        CommonCommand::Run(args) => run::handle_command(args),
        CommonCommand::Prove(args) => prove::handle_command(args),
        CommonCommand::Request(args) => request::handle_command(args),
        CommonCommand::Verify(args) => verify::handle_command(args),
        CommonCommand::PublicParams(args) => public_params::handle_command(args),
    }
}
