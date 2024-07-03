use std::env;
use uuid::Uuid;

#[derive(Default)]
pub enum ForProver {
    #[default]
    Default,
    Jolt,
}

pub struct CompileOpts {
    id: Uuid,
    linker_path: Option<PathBuf>,
    debug: bool,
    native: bool,
    source_path: Option<PathBuf>,
    memlimit: Option<usize>, // in mb
    prover: ForProver,
}

impl Default for CompileOpts {

    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            linker_path: None,
            debug: false,
            native: false,
            source_path: None,
            memlimit: Some(4),
            prover: ForProver::default(),
        }
    }
}

impl CompileOpts {

    fn debug(&mut self, debug: bool) -> () {
        self.debug = true;
    };

    fn native(&mut self, native: bool) -> () {
        self.native = true;
    };

    fn source_path(&mut self, source_path: PathBuf) -> () {
        self.source_path = Some(source_path);
    };

    fn memlimit(&mut self, memlimit: usize) -> () {
        self.memlimit = Some(memlimit);
    }

    fn prover(&mut self, prover: ForProver) -> () {
        self.prover = Some(prover);
    }

    fn set_linker(&mut self) -> Result<(), Error> {
        let linker_script_header = match self.prover {
            Jolt => {
                if self.memlimit.is_none() {
                    return JOLT_HEADER;
                }

                // throw error
            },
            Default => {
                if let Some(memlimit) = self.memlimit {
                    return DEFAULT_HEADER.replace("{MEMORY_SIZE}", memlimit.saturating_mul(0x100000 as u32).to_string())
                }

                // throw error
            },
        }

        let linker_script = LINKER_SCRIPT_TEMPLATE.replace("HEADER", linker_script_header);

        self.linker_path = PathBuf::from_str(&format!("/tmp/nexus-guest-linkers/{}.ld", self.id.to_string()))?;

        if let Some(parent) = self.linker_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(self.linker_path)?;
        file.write_all(linker_script.as_bytes())?;
    }

    fn build(&mut self) -> Result<PathBuf, Error> {
        // error if no source path

        self.set_linker();

        let rust_flags = [
            "-C",
            &format!("link-arg=-T{}", self.linker_path),
            "-C",
            "panic=abort",
        ];

        let target = "riscv32i-unknown-none-elf";
        let profile = if self.debug { "debug" } else { "release-unoptimized" };

        let output = Command::new("cargo")
            .args([
                "build",
                "--target=riscv32i-unknown-none-elf",
                "--profile",
                profile,
            ])
            .output()?;

        if !output.status.success() {
            io::stderr().write_all(&output.stderr)?;
        }

        let elf_path = format!("{}/{}/release/guest", target, toolchain);

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
