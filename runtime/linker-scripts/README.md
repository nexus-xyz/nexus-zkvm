### Linker scripts

`runtime` crate switches linker scripts based on `NEXUS_VM_PROVER` environment variable.

This is a temporary workaround: Jolt expects a memory to start at specific address. However, it doesn't fit RISC-V -> NexusVM translation.

The linker script should be reverted to a single file that fits both prover implementations.