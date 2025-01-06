use std::time::Duration;

use nexus_vm::{
    riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
    trace::{k_trace_direct, UniformTrace},
};
use nexus_vm_prover::trace::PreprocessedTraces;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

const K: usize = 1;

const LOG_SIZES: &[u32] = &[
    PreprocessedTraces::MIN_LOG_SIZE,
    // PreprocessedTracess::MIN_LOG_SIZE + 2,
    // PreprocessedTracess::MIN_LOG_SIZE + 4,
];

const _: () = {
    const MAX_LOG_SIZE: u32 = 20;

    let mut i = 0;
    while i < LOG_SIZES.len() {
        assert!(LOG_SIZES[i] >= PreprocessedTraces::MIN_LOG_SIZE && LOG_SIZES[i] <= MAX_LOG_SIZE);
        i += 1;
    }
};

criterion_group! {
    name = prove;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_prove,
}

criterion_main!(prove);

fn bench_prove(c: &mut Criterion) {
    for &log_size in LOG_SIZES {
        let program_trace = program_trace(log_size);

        let mut group = c.benchmark_group(format!("Prove-LogSize-{log_size}"));
        group.sample_size(20);

        group.bench_function("ComputeProof", |b| {
            b.iter(|| {
                nexus_vm_prover::Machine::<nexus_vm_prover::Components>::prove(black_box(
                    &program_trace,
                ))
            })
        });

        group.finish();
    }
}

fn program_trace(log_size: u32) -> UniformTrace {
    let mut i = 0u8;
    let mut j = 1u8;
    let mut k = 2u8;

    let insts = std::iter::once(Instruction::new_ir(
        Opcode::from(BuiltinOpcode::ADDI),
        1,
        0,
        1,
    ))
    .chain(std::iter::from_fn(|| {
        let inst = Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), k, j, i.into());
        const NUM_REGISTERS: u8 = {
            assert!(nexus_common::constants::NUM_REGISTERS <= u8::MAX as u32);
            nexus_common::constants::NUM_REGISTERS as u8
        };
        i = (i + 1) % NUM_REGISTERS;
        j = (j + 1) % NUM_REGISTERS;
        k = (k + 1) % NUM_REGISTERS;
        Some(inst)
    }))
    .take(1 << log_size)
    .collect();

    k_trace_direct(&vec![BasicBlock::new(insts)], K).expect("error generating trace")
}
