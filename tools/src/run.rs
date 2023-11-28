use nexus_riscv::*;

use crate::*;

pub fn run() -> CmdResult<()> {
    let Opts { command: Run { verbose, release, bin } } = options() else {
        panic!()
    };
    let t = get_target(*release, bin)?;

    let opts = VMOpts {
        k: 1,
        nop: None,
        loopk: None,
        file: Some(t),
    };

    Ok(run_vm(&opts, *verbose)?)
}
