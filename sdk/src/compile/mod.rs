use generic_array::ArrayLength;
use std::fs;
use std::io::Write;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str::FromStr;

use crate::error::BuildError;

/// Compilation and packaging for Rust guests via Cargo.
pub mod cargo;

/// A guest program packager.
pub trait Packager {
    type DigestSize: ArrayLength<u8>;

    /// Return the digest length the packager uses.
    fn digest_len() -> usize;
}

/// Dynamic compilation of guest programs.
///
/// By default, compilation occurs within `/tmp`. However, the implementation does respect the [`OUT_DIR`](https://doc.rust-lang.org/cargo/reference/environment-variables.html) environment variable.
#[derive(Clone)]
pub struct Compiler<P: Packager> {
    /// The (in-workspace) package to build.
    pub package: String,
    /// The binary produced by the build that should be loaded into the zkVM after successful compilation.
    pub binary: String,
    debug: bool,
    native: bool,
    unique: bool,
    _packager: PhantomData<P>,
}

/// An interface for dynamic compilation of guest programs.
pub trait Compile {
    /// Setup dynamic compilation.
    fn new(package: &str) -> Self;

    /// Setup dynamic compilation, using non-default binary name.
    fn new_with_custom_binary(package: &str, binary: &str) -> Self;

    /// Set dynamic compilation to build the guest program in a debug profile.
    fn set_debug_build(&mut self, debug: bool);

    /// Set dynamic compilation to build for the native (host machine) target, rather than for the zkVM.
    fn set_native_build(&mut self, native: bool);

    /// Set dynamic compilation to run a unique build that neither overwrites prior builds nor will be overwritten by future builds. May be used to concurrently build different versions of the same binary.
    ///
    /// Note: the SDK does not automatically clean or otherwise manage the resultant builds in the output directory.
    fn set_unique_build(&mut self, unique: bool);

    /// Set the linker script to use when building the guest binary.
    fn set_linker() -> Result<PathBuf, BuildError> {
        let linker_script = include_str!("./linker-scripts/default.x");

        let linker_path = PathBuf::from_str("/tmp/nexus-guest-linkers/default.ld").unwrap();

        if let Some(parent) = linker_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(linker_path.clone())?;
        file.write_all(linker_script.as_bytes())?;

        Ok(linker_path)
    }

    /// Compile and build the guest binary.
    fn build(&mut self) -> Result<PathBuf, BuildError>;
}
