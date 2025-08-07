use std::time::Duration;

use nexus_vm::{
    emulator::{InternalView, View},
    riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
    trace::{k_trace_direct, UniformTrace},
};
use nexus_vm_prover::{
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    machine::BaseComponent,
    trace::{
        program::iter_program_steps,
        program_trace::{ProgramTraceRef, ProgramTracesBuilder},
        sidenote::SideNote,
        PreprocessedTraces, TracesBuilder,
    },
    traits::{generate_interaction_trace, MachineChip},
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use stwo::core::channel::Blake2sChannel;

const K: usize = 1;

const LOG_SIZES: &[u32] = &[
    PreprocessedTraces::MIN_LOG_SIZE,
    PreprocessedTraces::MIN_LOG_SIZE + 2,
    PreprocessedTraces::MIN_LOG_SIZE + 4,
    PreprocessedTraces::MIN_LOG_SIZE + 6,
    PreprocessedTraces::MIN_LOG_SIZE + 8,
    PreprocessedTraces::MIN_LOG_SIZE + 10,
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
    name = trace_gen;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_trace_gen,
}

criterion_main!(trace_gen);

fn bench_trace_gen(c: &mut Criterion) {
    for &log_size in LOG_SIZES {
        let blocks = program_trace(log_size);
        let (view, execution_trace) = k_trace_direct(&blocks, K).expect("error generating trace");
        let program_info = view.get_program_memory();
        let ext_config = ExtensionsConfig::default();

        let mut group = c.benchmark_group(format!("TraceGen-LogSize-{log_size}"));
        group.sample_size(20);

        group.bench_function("PreprocessedTraces", |b| {
            b.iter(|| black_box(PreprocessedTraces::new(black_box(log_size))))
        });
        let preprocessed_trace = PreprocessedTraces::new(log_size);
        let program_trace_ref = ProgramTraceRef {
            program_memory: program_info,
            init_memory: view.get_initial_memory(),
            exit_code: view.get_exit_code(),
            public_output: view.get_public_output(),
        };
        let mut program_traces = ProgramTracesBuilder::new(log_size, program_trace_ref);

        group.bench_function("MainTrace", |b| {
            b.iter(|| {
                let mut prover_traces = TracesBuilder::new(black_box(log_size));
                fill_main_trace(
                    &mut prover_traces,
                    &execution_trace,
                    &mut program_traces,
                    black_box(&view),
                );
            })
        });

        let mut prover_traces = TracesBuilder::new(log_size);
        fill_main_trace(
            &mut prover_traces,
            &execution_trace,
            &mut program_traces,
            black_box(&view),
        );

        group.bench_function("FinalizeTrace", |b| {
            b.iter(|| {
                black_box(prover_traces.clone().finalize());
            })
        });
        let finalized_trace = prover_traces.finalize();
        let finalized_program_trace = program_traces.finalize();
        group.bench_function("InteractionTrace", |b| {
            b.iter(|| {
                let prover_channel = &mut black_box(Blake2sChannel::default());
                let mut lookup_elements = black_box(AllLookupElements::default());
                BaseComponent::draw_lookup_elements(
                    black_box(&mut lookup_elements),
                    black_box(prover_channel),
                    black_box(&ext_config),
                );

                black_box(generate_interaction_trace::<BaseComponent>(
                    black_box(&finalized_trace),
                    black_box(&preprocessed_trace),
                    black_box(&finalized_program_trace),
                    black_box(&lookup_elements),
                ))
            })
        });
        group.finish();
    }
}

fn fill_main_trace(
    prover_traces: &mut TracesBuilder,
    execution_trace: &UniformTrace,
    program_memory: &mut ProgramTracesBuilder,
    view: &View,
) {
    let mut prover_side_note = SideNote::new(program_memory, view);
    let program_steps = iter_program_steps(execution_trace, prover_traces.num_rows());
    let ext_config = ExtensionsConfig::default();
    for (row_idx, program_step) in black_box(program_steps.enumerate()) {
        BaseComponent::fill_main_trace(
            black_box(prover_traces),
            black_box(row_idx),
            black_box(&program_step),
            black_box(&mut prover_side_note),
            black_box(&ext_config),
        )
    }
}

fn program_trace(log_size: u32) -> Vec<BasicBlock> {
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
    .take(2usize.pow(log_size))
    .collect();
    vec![BasicBlock::new(insts)]
}
