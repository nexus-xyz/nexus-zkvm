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
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la sp, __memory_top - 4
    mv fp, sp

    jal ra, _get_stack_size
    blez a0, run /* if returned stack size is lte to zero, ignore */

    addi a0, a0, -4
    mv sp, a0
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

.globl alloc_
alloc_:
    lw s0, _heap
    add a0, a0, s0
    bgeu a0, sp, abort
    la s1, _heap
    sw a0, 0(s1)
    mv a0, s0
    ret
