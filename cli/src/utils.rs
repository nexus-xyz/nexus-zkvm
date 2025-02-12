use std::{ffi::OsStr, path::Path, process::Command};

pub fn cargo<I, S>(dir: Option<&Path>, args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_err| "cargo".into());

    let status = Command::new(cargo_bin)
        .args(args)
        .current_dir(dir.unwrap_or(Path::new(".")))
        .status()?;
    if !status.success() {
        anyhow::bail!("cargo didn't exit successfully: {status}")
    }
    Ok(())
}
