// Entry point of all programs (_start).

// We assume the Nexus VM is initialized according to the
// machine description and ABI=ilp32. In particular:
//  - all memory is initialized (bss cleared)
//  - pc = 0x1000
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

    li sp, 0xffffffff
    mv fp, sp

    jal ra, _start_rust

.globl abort
abort:
    unimp

.globl alloc_
alloc_:
    lw s0, _heap
    add a0, a0, s0
    la s0, _heap
    sw a0, 0(s0)
    ret
