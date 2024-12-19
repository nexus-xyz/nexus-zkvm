use std::time::Duration;

use nexus_vm::{
    emulator::{LinearEmulator, LinearMemoryLayout},
    riscv::{BasicBlock, BuiltinOpcode, Instruction, InstructionType, Opcode},
    trace::k_trace_direct,
};
use nexus_vm_prover::{
    trace::{
        program::iter_program_steps, program_trace::ProgramTraces, sidenote::SideNote,
        PreprocessedTraces, Traces,
    },
    traits::MachineChip,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use stwo_prover::{constraint_framework::logup::LookupElements, core::channel::Blake2sChannel};

const K: usize = 1;

const LOG_SIZES: &[u32] = &[
    PreprocessedTraces::MIN_LOG_SIZE,
    PreprocessedTraces::MIN_LOG_SIZE + 2,
    PreprocessedTraces::MIN_LOG_SIZE + 4,
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
    name = interaction_trace;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_interaction_trace,
}

criterion_main!(interaction_trace);

fn bench_interaction_trace(c: &mut Criterion) {
    let blocks = program_trace();
    let program_trace = k_trace_direct(&blocks, K).expect("error generating trace");

    let emulator = LinearEmulator::from_basic_blocks(LinearMemoryLayout::default(), &blocks);
    for &log_size in LOG_SIZES {
        let mut group = c.benchmark_group(format!("Interaction-Trace-LogSize-{log_size}"));
        group.sample_size(10);

        let program_traces = ProgramTraces::new(log_size, emulator.get_program_memory());
        let preprocessed_trace = PreprocessedTraces::new(log_size);
        let mut prover_traces = Traces::new(log_size);
        let mut prover_side_note = SideNote::new(&program_traces);

        let program_steps = iter_program_steps(&program_trace, prover_traces.num_rows());
        for (row_idx, program_step) in program_steps.enumerate() {
            nexus_vm_prover::Components::fill_main_trace(
                &mut prover_traces,
                row_idx,
                &program_step,
                &program_traces,
                &mut prover_side_note,
            );
        }

        let prover_channel = &mut Blake2sChannel::default();
        let lookup_elements = LookupElements::draw(prover_channel);

        group.bench_function("Fill", |b| {
            b.iter(|| {
                black_box(nexus_vm_prover::Components::fill_interaction_trace(
                    black_box(&prover_traces),
                    black_box(&preprocessed_trace),
                    black_box(&program_traces),
                    black_box(&lookup_elements),
                ))
            })
        });
        group.finish();
    }
}

fn program_trace() -> Vec<BasicBlock> {
    let mut i = 0u8;
    let mut j = 1u8;
    let mut k = 2u8;

    let insts = std::iter::once(Instruction::new(
        Opcode::from(BuiltinOpcode::ADDI),
        1,
        0,
        1,
        InstructionType::IType,
    ))
    .chain(std::iter::from_fn(|| {
        let inst = Instruction::new(
            Opcode::from(BuiltinOpcode::ADD),
            k,
            j,
            i.into(),
            InstructionType::RType,
        );
        const NUM_REGISTERS: u8 = {
            assert!(nexus_common::constants::NUM_REGISTERS <= u8::MAX as u32);
            nexus_common::constants::NUM_REGISTERS as u8
        };
        i = (i + 1) % NUM_REGISTERS;
        j = (j + 1) % NUM_REGISTERS;
        k = (k + 1) % NUM_REGISTERS;
        Some(inst)
    }))
    .take(2usize.pow(14))
    .collect();
    vec![BasicBlock::new(insts)]
}
