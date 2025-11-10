use crypto_common::generic_array::typenum::{ToInt, U32};
use std::io;
use std::io::Write;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use uuid::Uuid;

pub use crate::error::BuildError;

use super::{Compile, Compiler, Packager};

/// The Cargo guest program packager, used for Rust.
pub enum CargoPackager {}
impl Packager for CargoPackager {
    type DigestSize = U32;

    fn digest_len() -> usize {
        let sz: u32 = Self::DigestSize::to_int();
        sz as usize
    }
}

impl Compile for Compiler<CargoPackager> {
    /// Configure dynamic compilation.
    fn new(package: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: package.to_string(),
            debug: false,
            native: false,
            unique: false,
            _packager: PhantomData,
        }
    }

    /// Configure dynamic compilation, using non-default binary name.
    fn new_with_custom_binary(package: &str, binary: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: binary.to_string(),
            debug: false,
            native: false,
            unique: false,
            _packager: PhantomData,
        }
    }

    /// Set dynamic compilation to build the guest program in a debug profile.
    fn set_debug_build(&mut self, debug: bool) {
        self.debug = debug;
    }

    /// Set dynamic compilation to build for the native (host machine) target, rather than for the zkVM.
    fn set_native_build(&mut self, native: bool) {
        self.native = native;
    }

    /// Set dynamic compilation to run a unique build that neither overwrites prior builds nor will be overwritten by future builds. May be used to concurrently build different versions of the same binary.
    ///
    /// Note: the SDK does not automatically clean or otherwise manage the resultant builds in the output directory.
    fn set_unique_build(&mut self, unique: bool) {
        self.unique = unique;
    }

    /// Compile and build the guest binary.
    fn build(&mut self) -> Result<PathBuf, BuildError> {
        let linker_path = Compiler::set_linker()?;

        let rust_flags = [
            "-C",
            "relocation-model=pic",
            "-C",
            &format!("link-arg=-T{}", linker_path.display()),
            "-C",
            "panic=abort",
        ];

        let target = if self.native {
            "native"
        } else {
            "riscv32im-unknown-none-elf"
        };

        let profile = if self.debug { "debug" } else { "release" };

        let cargo_encoded_rustflags = rust_flags.join("\x1f");
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

        // Base args
        cmd.env("CARGO_ENCODED_RUSTFLAGS", cargo_encoded_rustflags)
            .args([
                "build",
                "--package",
                self.package.as_str(),
                "--bin",
                prog,
                "--target-dir",
                &dest,
            ]);

        // Only specify a --target for cross compilation; for native builds Cargo should infer host target.
        if !self.native {
            cmd.args(["--target", target]);
        }

        // Profile selection
        cmd.args(["--profile", profile]);

        let res = cmd.output()?;

        if !res.status.success() {
            io::stderr().write_all(&res.stderr)?;
            return Err(BuildError::CompilerError);
        }

        // Compute output artifact path differently for native vs cross builds
        let elf_path = if self.native {
            PathBuf::from_str(&format!("{}/{}/{}", dest, profile, prog)).unwrap()
        } else {
            PathBuf::from_str(&format!("{}/{}/{}/{}", dest, target, profile, prog)).unwrap()
        };

        Ok(elf_path)
    }
}
