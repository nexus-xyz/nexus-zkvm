// Entry point of all programs (_start).

// We assume the Nexus VM is initialized according to the
// machine description and ABI=ilp32. In particular:
//  - all memory is initialized (bss cleared)
//  - pc = set according to ELF file
//  - a0-a7 = program arguments
//  - all other registers set to zero

// The intention is to keep the startup code minimal

.option nopic
.section .init, "ax"
.global _start
.extern __memory_top
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la sp, __memory_top - 4 /* default to growing the stack (down) from here */
    jal ra, _overwrite_sp   /* but make an ecall to potentially overwrite it */
    mv fp, sp

    j run

run:
    jal ra, _start_rust
    /* halt with result of main in a0 */
    unimp

.globl abort
abort:
    li a0, 1     /* indicate error */
    unimp
