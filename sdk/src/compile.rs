use std::fmt::Display;
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use uuid::Uuid;

pub use crate::error::BuildError;

#[doc(hidden)]
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

/// Options for dynamic compilation of guest programs.
///
/// By default, compilation occurs within `/tmp`. However, the implementation does respect the [`OUT_DIR`](https://doc.rust-lang.org/cargo/reference/environment-variables.html) environment variable.
#[derive(Clone)]
pub struct CompileOpts {
    /// The (in-workspace) package to build.
    pub package: String,
    /// The binary produced by the build that should be loaded into the zkVM after successful compilation.
    pub binary: String,
    debug: bool,
    //native: bool,
    unique: bool,
    pub(crate) memlimit: Option<usize>, // in mb
}

impl CompileOpts {
    /// Setup options for dynamic compilation.
    pub fn new(package: &str, binary: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: binary.to_string(),
            debug: false,
            //native: false,
            unique: false,
            memlimit: None,
        }
    }

    /// Set dynamic compilation to build the guest program in a debug profile.
    pub fn set_debug_build(&mut self, debug: bool) {
        self.debug = debug;
    }

    // NOTE: SDK should be enhanced to support native building once feature parity is achieved for the runtime.
    //   (see, https://github.com/nexus-xyz/nexus-zkvm/pull/195#discussion_r1646697743)
    //
    // /// Set dynamic compilation to build for the native (host machine) target, rather than for the zkVM.
    // pub fn set_native_build(&mut self, native: bool) {
    //     self.native = native;
    // }

    /// Set dynamic compilation to run a unique build that neither overwrites prior builds nor will be overwritten by future builds. May be used to concurrently build different versions of the same binary.
    ///
    /// Note: the SDK does not automatically clean or otherwise manage the resultant builds in the output directory.
    pub fn set_unique_build(&mut self, unique: bool) {
        self.unique = unique;
    }

    /// Set the amount of memory available to the guest program. For certain provers increasing the memory limit can lead to corresponding increases in the required proving time.
    ///
    /// Compilation will fail if this option is set when compiling for use with [`Jolt`](crate::jolt::Jolt), which uses a fixed memory size.
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

        // (see comment above on `set_native_build`)
        //
        // let target = if self.native {
        //     "native"
        // } else {
        //     "riscv32i-unknown-none-elf"
        // };
        let target = "riscv32i-unknown-none-elf";

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

        let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_err| "cargo".into());
        let mut cmd = Command::new(cargo_bin);

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

        let elf_path =
            PathBuf::from_str(&format!("{}/{}/{}/{}", dest, target, profile, prog)).unwrap();

        Ok(elf_path)
    }
}
