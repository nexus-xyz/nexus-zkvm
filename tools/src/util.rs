use std::env;
use std::fmt::Display;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use cargo_metadata::MetadataCommand;

#[derive(Debug)]
pub struct CmdErr(pub String);

pub type CmdResult<T> = Result<T, CmdErr>;

impl<T: Display> From<T> for CmdErr {
    fn from(x: T) -> Self {
        Self(format!("{}", x))
    }
}

pub fn cargo(dir: Option<&PathBuf>, args: &[&str]) -> CmdResult<()> {
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

pub fn write_file(path: PathBuf, contents: &[u8]) -> CmdResult<()> {
    if let Some(dir) = path.parent() {
        create_dir_all(dir)?
    }
    Ok(File::create(path)?.write_all(contents)?)
}

pub fn get_target(release: bool, bin: &Option<String>) -> CmdResult<PathBuf> {
    let md = MetadataCommand::new().exec()?;

    let pkg = md.root_package().ok_or("no root package")?;
    let ts = pkg
        .targets
        .iter()
        .filter(|t| t.kind.contains(&"bin".to_string()))
        .map(|t| t.name.clone())
        .collect::<Vec<_>>();

    let mut path = PathBuf::from(&md.target_directory);
    path.push("riscv32i-unknown-none-elf");
    if release {
        path.push("release");
    } else {
        path.push("debug");
    }

    if ts.len() == 1 {
        path.push(&ts[0]);
        return Ok(path);
    }

    let name = if let Some(n) = bin {
        n
    } else if let Some(n) = &pkg.default_run {
        n
    } else {
        return Err(format!("--bin must be one of {:?}", ts).into());
    };

    for t in &ts {
        if t == name {
            path.push(name);
            return Ok(path);
        }
    }
    Err("target not found".into())
}
