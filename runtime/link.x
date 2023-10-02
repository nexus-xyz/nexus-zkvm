
MEMORY {
  PROG (rx) : ORIGIN = 0x1000,     LENGTH = 0x10000000 - 0x1000
  HEAP (rw) : ORIGIN = 0x10000000, LENGTH = 0x80000000 - 0x10000000
}

REGION_ALIAS("REGION_TEXT",   PROG);
REGION_ALIAS("REGION_DATA",   HEAP);
REGION_ALIAS("REGION_BSS",    HEAP);

SECTIONS
{
  .text : ALIGN(4)
  {
    KEEP(*(.init));
    . = ALIGN(4);
    KEEP(*(.init.rust));
    *(.text .text.*);
  } > REGION_TEXT

  .data : ALIGN(4)
  {
    /* Must be called __global_pointer$ for linker relaxations to work. */
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);

    /* this is used by the global allocator (see:src/lib.rs) */
    . = ALIGN(4);
    _heap = .;
    LONG(_ebss);
  } > REGION_DATA

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(4);
    _ebss = .;
  } > REGION_BSS

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

ASSERT(SIZEOF(.got) == 0, "
.got section detected in the input files. Dynamic relocations are not
supported. If you are linking to C code compiled using the `gcc` crate
then modify your build script to compile the C code _without_ the
-fPIC flag. See the documentation of the `gcc::Config.fpic` method for
details.");
