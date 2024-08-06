use std::{
    fmt::Display,
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
    str::FromStr,
};
use uuid::Uuid;

use nexus_core::prover::jolt::Attributes;

// second entry is max_log_size
type ExtAttributes = (Attributes, u32);

pub use crate::error::BuildError;

#[doc(hidden)]
#[derive(Default, PartialEq)]
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
    verbose: bool,
    debug: bool,
    //native: bool,
    unique: bool,
    pub(crate) memlimit: Option<usize>, // in mb
}

impl CompileOpts {
    /// Setup options for dynamic compilation.
    pub fn new(package: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: package.to_string(),
            verbose: false,
            debug: false,
            //native: false,
            unique: false,
            memlimit: None,
        }
    }

    /// Setup options for dynamic compilation, using non-default binary name.
    pub fn new_with_custom_binary(package: &str, binary: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: binary.to_string(),
            verbose: false,
            debug: false,
            //native: false,
            unique: false,
            memlimit: None,
        }
    }

    /// Set dynamic compilation to always print the output of rustc when building the guest program.
    ///
    /// Even without this flag set the output of rustc will be printed for a failed build.
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
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

    /// Set the amount of memory available to the guest program in mb. For certain provers increasing the memory limit can lead to corresponding increases in the required proving time.
    ///
    /// Compilation will fail if this option is set when compiling for use with [`Jolt`](crate::jolt::Jolt), which uses a fixed memory size.
    ///
    /// The memory limit can also be set using an argument to the `nexus_rt::main` macro (e.g., `#[nexus_rt::main(memlimit = 16)]`). The SDK _will not_ overwrite such a hardcoded value.
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

        // (see comment above on `set_native_build`)
        //
        // let target = if self.native {
        //     "native"
        // } else {
        //     "riscv32i-unknown-none-elf"
        // };
        let target = "riscv32i-unknown-none-elf";

        let profile = if self.debug { "debug" } else { "release" };

        let mut dest = match std::env::var_os("OUT_DIR") {
            Some(path) => path.into_string().unwrap(),
            None => "/tmp/nexus-target".into(),
        };

        if self.unique {
            let uuid = Uuid::new_v4();
            dest = format!("{}-{}", dest, uuid);
        }

        let prog = self.binary.as_str();

        let base_args = [
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
        ];

        let base_rust_flags = [
            "-C",
            &format!("link-arg=-T{}", linker_path.display()),
            "-C",
            "panic=abort",
        ];

        let mut args = vec![];
        args.extend(base_args);

        let mut rust_flags = vec![];
        rust_flags.extend(base_rust_flags);

        // HACK: We need to get the attr path to the proc_macro builders.
        //       The "right" way to do this is to use a build script, but
        //       in our case it'll be user facing and might well confuse,
        //       especially as the user can want to write/use their own.
        //
        //       The ideal way to do this will be to use `--set-env` once
        //       stabilized with a custom environment variable. While not
        //       ideal, for the moment we can instead pass it through cfg
        //       and then parse it out of CARGO_ENCODED_RUSTFLAGS to use.
        let attr_path = [dest.clone(), String::from(".jolt.attr")].join("/");
        let attr_cfg = format!("compile_config_dir=\"{}\"", &attr_path);

        if prover == &ForProver::Jolt {
            args.extend(["--features", "jolt-io"]);
            rust_flags.append(&mut vec!["--cfg", &attr_cfg]);

            let memory_size = nexus_core::prover::jolt::constants::DEFAULT_MEMORY_SIZE;
            let stack_size = nexus_core::prover::jolt::constants::DEFAULT_STACK_SIZE;
            let max_input_size = nexus_core::prover::jolt::constants::DEFAULT_MAX_INPUT_SIZE;
            let max_output_size = nexus_core::prover::jolt::constants::DEFAULT_MAX_OUTPUT_SIZE;
            let max_log_size = nexus_core::prover::jolt::constants::DEFAULT_MAX_OUTPUT_SIZE;

            let attr: ExtAttributes = (
                Attributes {
                    wasm: false,
                    memory_size,
                    stack_size,
                    max_input_size,
                max_output_size,
                }, max_log_size
            );
            let attr_bytes = postcard::to_stdvec(&attr).map_err(BuildError::ConfigError)?;

            let mut mkdir = Command::new("mkdir");
            mkdir.args(["-p", &dest]);

            let res = mkdir.output()?;

            if !res.status.success() {
                io::stderr().write_all(&res.stderr)?;
                return Err(BuildError::IOError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unable to write configuration into build direectory",
                )));
            }

            match fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(attr_path.clone())
            {
                Ok(mut fp) => {
                    if let Err(e) = fp.write_all(attr_bytes.as_slice()) {
                        return Err(e).map_err(BuildError::IOError);
                    };
                }
                Err(e) => {
                    return Err(e).map_err(BuildError::IOError);
                }
            }
        }

        if self.verbose {
            args.extend(["--verbose"]);
        }

        let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_err| "cargo".into());
        let envs = vec![("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f"))];

        let mut cmd = Command::new(cargo_bin);
        let res = cmd.envs(envs).args(&args).output()?;

        if self.verbose || !res.status.success() {
            io::stderr().write_all(&res.stderr)?;
        }

        if !res.status.success() {
            return Err(BuildError::CompilerError);
        }

        let elf_path =
            PathBuf::from_str(&format!("{}/{}/{}/{}", dest, target, profile, prog)).unwrap();

        Ok(elf_path)
    }
}
