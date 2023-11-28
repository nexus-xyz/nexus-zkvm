use crate::*;
use std::path::Path;

const CONFIG: &[u8] = include_bytes!("config.toml");
const SRC: &[u8] = include_bytes!("template.rs");

fn write_to_file(root: &Path, dir: &str, file: &str, contents: &[u8]) -> CmdResult<()> {
    let mut path = root.to_path_buf();
    path.push(dir);
    path.push(file);
    write_file(path, contents)?;
    Ok(())
}

pub fn new() -> CmdResult<()> {
    let Opts { command: New { path } } = options() else {
        panic!()
    };

    // run cargo to setup project
    cargo(None, &["new", path.to_str().ok_or("invalid path")?])?;
    cargo(
        Some(path),
        &[
            "add",
            "--git",
            "ssh://git@github.com:22/nexus-xyz/nexus-zkvm.git",
            "nexus-rt",
        ],
    )?;

    // write .cargo/config
    write_to_file(path, ".cargo", "config.toml", CONFIG)?;

    // write src/main.rs
    write_to_file(path, "src", "main.rs", SRC)
}
