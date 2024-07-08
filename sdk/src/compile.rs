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
            Self::Jolt => write!(f, "jolt")
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
    pub(crate) debug: bool,
    pub(crate) native: bool,
    pub(crate) memlimit: Option<usize>, // in mb
}

impl CompileOpts {
    pub fn new(package: &str, binary: &str) -> Self {
        Self {
            package: package.to_string(),
            binary: binary.to_string(),
            debug: false,
            native: false,
            memlimit: None,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn set_native(&mut self, native: bool) {
        self.native = native;
    }

    pub fn set_memlimit(&mut self, memlimit: usize) {
        self.memlimit = Some(memlimit);
    }

    fn set_linker(&mut self, prover: &ForProver) -> Result<PathBuf, BuildError> {
        let linker_script_header = match prover {
            ForProver::Jolt => {
                if self.memlimit.is_some() {
                    return Err(BuildError::InvalidMemoryConfiguration);
                }

                JOLT_HEADER.into()
            }
            ForProver::Default => {
                if self.memlimit.is_none() {
                    return Err(BuildError::InvalidMemoryConfiguration);
                }

                DEFAULT_HEADER.replace(
                    "{MEMORY_LIMIT}",
                    &format!("0x{:X}", &(self.memlimit.unwrap() as u32).saturating_mul(0x100000))
                )
            }
        };

        let linker_script = LINKER_SCRIPT_TEMPLATE.replace("{HEADER}", &linker_script_header);

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
        let uuid = Uuid::new_v4();
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
        let dest = format!("/tmp/nexus-target-{}", uuid);

        let mut cmd = Command::new("cargo");
        cmd.envs(envs)
            .args([
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
            PathBuf::from_str(&format!("/tmp/nexus-target-{}/{}/{}/{}", uuid, target, profile, prog)).unwrap();

        Ok(elf_path)
    }
}

const LINKER_SCRIPT_TEMPLATE: &str = r#"
ENTRY(_start);

SECTIONS
{
  {HEADER}

  .data : ALIGN(4)
  {
    /* Must be called __global_pointer$ for linker relaxations to work. */
    __global_pointer$ = . + 0x800;
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);

    /* this is used by the global allocator (see:src/lib.rs) */
    . = ALIGN(4);
    _heap = .;
    LONG(_ebss);
  }

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(4);
    _ebss = .;
  }

  /* Dynamic relocations are unsupported. This section is only used to detect
     relocatable code in the input files and raise an error if relocatable code
     is found */
  .got (INFO) :
  {
    KEEP(*(.got .got.*));
  }

  /DISCARD/ :
  {
    *(.comment*)
    *(.debug*)
  }

  /* Stack unwinding is not supported, but we will keep these for now */
  .eh_frame (INFO) : { KEEP(*(.eh_frame)) }
  .eh_frame_hdr (INFO) : { *(.eh_frame_hdr) }
}

ASSERT(. < __memory_top, "Program is too large for the VM memory.");

ASSERT(SIZEOF(.got) == 0, "
.got section detected in the input files. Dynamic relocations are not
supported. If you are linking to C code compiled using the `gcc` crate
then modify your build script to compile the C code _without_ the
-fPIC flag. See the documentation of the `gcc::Config.fpic` method for
details.");
"#;

const DEFAULT_HEADER: &str = r#"__memory_top = {MEMORY_LIMIT};
  . = 0;

  .text : ALIGN(4)
  {
    KEEP(*(.init));
    . = ALIGN(4);
    KEEP(*(.init.rust));
    *(.text .text.*);
  }

  . = ALIGN(8);
  . = .* 2;
"#;

const JOLT_HEADER: &str = r#"__memory_top = 0x80400000;
  . = 0x80000000;

  .text : ALIGN(4)
  {
    KEEP(*(.init));
    . = ALIGN(4);
    KEEP(*(.init.rust));
    *(.text .text.*);
  }

  . = ALIGN(8);
  /* . = .* 2; */
"#;
