mod new;
mod options;
mod util;

pub use options::*;
pub use util::*;

fn main() -> CmdResult {
    match &options().command {
        New { .. } => new::new(),
        cmd => {
            println!("Not Yet Implemented: {:?}", cmd);
            Err("TODO".into())
        }
    }
}
