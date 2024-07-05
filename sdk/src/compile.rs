use std::io;
use std::io::Write;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

#[derive(Default)]
pub enum ForProver {
    #[default]
    Default,
    Jolt,
}

pub struct CompileOpts {
    debug: bool,
    native: bool,
    source_path: PathBuf,
    memlimit: Option<usize>, // in mb
}

#[derive(Debug)]
pub enum BuildError {
    /// The compile options are invalid
    ConfigError,

    /// An error occured reading file system
    IOError(std::io::Error),

    /// The compilation process failed
    CompilerError,
}

impl CompileOpts {

    pub fn new(source_path: PathBuf) -> Self {
        Self {
            debug: false,
            native: false,
            source_path,
            memlimit: None,
        }
    }

    pub fn set_debug(&mut self, debug: bool) -> () {
        self.debug = true;
    }

    pub fn set_native(&mut self, native: bool) -> () {
        self.native = true;
    }

    pub fn set_memlimit(&mut self, memlimit: usize) -> () {
        self.memlimit = Some(memlimit);
    }

    fn set_linker(&mut self, id: &Uuid, prover: &ForProver) -> Result<PathBuf, BuildError> {
        let linker_script_header = match prover {
            Jolt => {
                if self.memlimit.is_none() {
                    return JOLT_HEADER;
                }

                return Err(BuildError::ConfigError);
            },
            Default => {
                if let Some(memlimit) = self.memlimit {
                    return DEFAULT_HEADER.replace("{MEMORY_SIZE}", memlimit.saturating_mul(0x100000 as u32).to_string())
                }

                return Err(BuildError::ConfigError);
            },
        };

        let linker_script = LINKER_SCRIPT_TEMPLATE.replace("{HEADER}", linker_script_header);

        let linker_path = PathBuf::from_str(&format!("/tmp/nexus-guest-linkers/{}.ld", id.to_string()))?;

        if let Some(parent) = linker_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = fs::File::create(linker_path)?;
        file.write_all(linker_script.as_bytes())?;

        linker_path
    }

    pub(crate) fn build(&mut self, prover: &ForProver) -> Result<PathBuf, BuildError> {
        let uuid = Uuid::new_v4();
        let linker_path = self.set_linker(&uuid, prover);

        let rust_flags = [
            "-C",
            &format!("link-arg=-T{}", linker_path),
            "-C",
            "panic=abort",
        ];

        let target = if self.native { "native" } else { "riscv32i-unknown-none-elf" };
        let profile = if self.debug { "debug" } else { "release-unoptimized" };

        let mut envs = vec![
            ("CARGO_ENCODED_RUSTFLAGS", rust_flags.join("\x1f")),
        ];

        let dest = format!(
            "/tmp/nexus-target-{}",
            uuid.to_string(),
        );

        let output = Command::new("cargo")
            .envs(envs)
            .args([
                "build",
                "--target-dir",
                &dest,
                "--target",
                target,
                "--profile",
                profile,
            ])
            .output()?;

        if !output.status.success() {
            io::stderr().write_all(&output.stderr)?;
            return Err(BuildError::CompileError);
        }

        let elf_path = format!("target/{}/{}/{}", target, profile, uuid.to_string());
        elf_path
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

const DEFAULT_HEADER: &str = r#"
  __memory_top = {MEMORY_LIMIT};
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

const JOLT_HEADER: &str = r#"
  __memory_top = 0x80400000;
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
