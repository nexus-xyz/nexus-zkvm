mod options;
mod util;
mod new;
mod run;
mod prove;

pub use options::*;
pub use util::*;

fn main() {
    let res = match &options().command {
        New { .. } => new::new(),
        Run { .. } => run::run(),
        Prove { .. } => prove::prove(),
        Query { .. } => prove::query(),
        Verify { .. } => prove::verify(),
        LocalProve { .. } => prove::local(),
        cmd => Err(format!("Not Yet Implemented: {:?}", cmd).into()),
    };

    match res {
        Ok(_) => (),
        Err(CmdErr(s)) => eprintln!("{}", s),
    }
}
