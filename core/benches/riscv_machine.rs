use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use nexus_core::nvm::{self, memory::Memory, memory::MerkleTrie, memory::Paged, VMOpts};
use std::hint::black_box;

fn trace_riscv_machine<M: Memory>(machine: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut vmopts = VMOpts::default();
    vmopts.machine = Some(machine.to_string());
    vmopts.k = 1;

    nvm::trace_vm::<M>(&vmopts, false, false, false)?;

    Ok(())
}

#[library_benchmark]
#[benches::multiple("nop10", "loop10", "branch", "jump", "ldst", "shift", "sub", "priv")]
fn bench_trace_riscv_machine_with_unchecked_memory(machine: &str) {
    black_box(
        trace_riscv_machine::<Paged>(machine).expect("Failed to trace RISC-V VM with Paged memory"),
    );
}

#[library_benchmark]
#[benches::multiple("nop10", "loop10", "branch", "jump", "ldst", "shift", "sub", "priv")]
fn bench_trace_riscv_machine_with_checked_memory(machine: &str) {
    black_box(
        trace_riscv_machine::<MerkleTrie>(machine)
            .expect("Failed to trace RISC-V VM with MerkleTrie memory"),
    );
}

library_benchmark_group!(
    name = bench_riscv_emulator;
    benchmarks = bench_trace_riscv_machine_with_unchecked_memory, bench_trace_riscv_machine_with_checked_memory
);

main!(library_benchmark_groups = bench_riscv_emulator);
