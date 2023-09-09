use std::env::{self, VarError};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};

#[derive(Debug)]
pub struct CmdErr(String);

macro_rules! from_ty {
    ($t:ty) => {
        impl From<$t> for CmdErr {
            fn from(x: $t) -> CmdErr {
                CmdErr(format!("{}", x))
            }
        }
    };
}

from_ty!(&str);
from_ty!(String);
from_ty!(VarError);
from_ty!(std::io::Error);
from_ty!(ExitStatus);

pub type CmdResult = std::result::Result<(), CmdErr>;

fn cmd_result<T, E>(r: Result<T, E>) -> CmdResult
where
    CmdErr: From<E>,
{
    match r {
        Ok(_) => Ok(()),
        Err(e) => Err(CmdErr::from(e)),
    }
}

pub fn cargo(dir: Option<&PathBuf>, args: &[&str]) -> CmdResult {
    if Command::new(env::var("CARGO")?)
        .args(args)
        .current_dir(dir.unwrap_or(&PathBuf::from(".")))
        .status()?
        .success()
    {
        Ok(())
    } else {
        Err("Cargo command failed".into())
    }
}

pub fn write_file(path: PathBuf, contents: &[u8]) -> CmdResult {
    if let Some(dir) = path.parent() {
        create_dir_all(dir)?
    }
    cmd_result(File::create(path)?.write_all(contents))
}
