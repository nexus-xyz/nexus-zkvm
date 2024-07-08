use std::fmt::Display;
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Default)]
pub enum ForProver {
    #[default]
    Default,
    Jolt,
}

impl Display for ForProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Jolt => write!(f, "jolt"),
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    /// The compile options are invalid for the memory limit
    InvalidMemoryConfiguration,

    /// An error occured reading file system
    IOError(std::io::Error),

    /// The compilation process failed
    CompilerError,
}

impl From<std::io::Error> for BuildError {
    fn from(x: std::io::Error) -> BuildError {
        BuildError::IOError(x)
    }
}

impl Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMemoryConfiguration => {
                write!(f, "invalid memory configuration for selected prover")
            }
            Self::IOError(error) => write!(f, "{}", error),
            Self::CompilerError => write!(f, "unable to compile using rustc"),
        }
    }
}

#[derive(Clone)]
pub struct CompileOpts {
    pub package: String,
    pub binary: String,
    debug: bool,
    native: bool,
    unique: bool,
    pub(crate) memlimit: Option<usize>, // in mb
}

impl CompileOpts {
    pub fn new(package: &str, binary: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: binary.to_string(),
            debug: false,
            native: false,
            unique: false,
            memlimit: None,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn set_native(&mut self, native: bool) {
        self.native = native;
    }

    pub fn set_unique(&mut self, unique: bool) {
        self.unique = unique;
    }

    pub fn set_memlimit(&mut self, memlimit: usize) {
        self.memlimit = Some(memlimit);
    }

    fn set_linker(&mut self, prover: &ForProver) -> Result<PathBuf, BuildError> {
        let linker_script = match prover {
            ForProver::Jolt => {
                if self.memlimit.is_some() {
                    return Err(BuildError::InvalidMemoryConfiguration);
                }

                include_str!("./linker-scripts/jolt.x").into()
            }
            ForProver::Default => {
                if self.memlimit.is_none() {
                    return Err(BuildError::InvalidMemoryConfiguration);
                }

                include_str!("./linker-scripts/default.x").replace(
                    "{MEMORY_LIMIT}",
                    &format!(
                        "0x{:X}",
                        &(self.memlimit.unwrap() as u32).saturating_mul(0x100000)
                    ),
                )
            }
        };

        let linker_path =
            PathBuf::from_str(&format!("/tmp/nexus-guest-linkers/{}.ld", prover)).unwrap();

        if let Some(parent) = linker_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(linker_path.clone())?;
        file.write_all(linker_script.as_bytes())?;

        Ok(linker_path)
    }

    pub(crate) fn build(&mut self, prover: &ForProver) -> Result<PathBuf, BuildError> {
        let linker_path = self.set_linker(prover)?;

        let rust_flags = [
            "-C",
            &format!("link-arg=-T{}", linker_path.display()),
            "-C",
            "panic=abort",
        ];

        let target = if self.native {
            "native"
        } else {
            "riscv32i-unknown-none-elf"
        };

        let profile = if self.debug {
            "debug"
        } else {
            "release-unoptimized"
        };

        let envs = vec![("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))];
        let prog = self.binary.as_str();

        let mut dest = match std::env::var_os("OUT_DIR") {
            Some(path) => path.into_string().unwrap(),
            None => "/tmp/nexus-target".into(),
        };

        if self.unique {
            let uuid = Uuid::new_v4();
            dest = format!("{}-{}", dest, uuid);
        }

        let mut cmd = Command::new("cargo");
        cmd.envs(envs).args([
            "build",
            "--package",
            self.package.as_str(),
            "--bin",
            prog,
            "--target-dir",
            &dest,
            "--target",
            target,
            "--profile",
            profile,
        ]);

        let res = cmd.output()?;

        if !res.status.success() {
            io::stderr().write_all(&res.stderr)?;
            return Err(BuildError::CompilerError);
        }

        let elf_path = PathBuf::from_str(&format!(
            "{}/{}/{}/{}",
            dest, target, profile, prog
        ))
        .unwrap();

        Ok(elf_path)
    }
}
