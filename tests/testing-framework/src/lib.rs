#[cfg(test)]
mod test {
    use nexus_common::word_align;
    use nexus_common_testing::emulator::{
        compile_multi, emulate, parse_output, EmulatorType, IOArgs, Input, Output,
    };
    use nexus_common_testing::program_trace;
    use nexus_vm::elf::ElfFile;
    use nexus_vm::trace::{k_trace, k_trace_direct};
    use nexus_vm_prover::{prove, verify};
    use postcard::to_allocvec;
    use serial_test::serial;

    const K: usize = 1;

    const EXAMPLES: &[&str] = &[
        "fact",
        "fib",
        "fib1000",
        "main",
        "palindromes",
        "galeshapley",
        "lambda_calculus",
        "keccak",
    ];

    fn emulate_wrapper<T: Input, U: Input, V: Output>(
        elfs: Vec<ElfFile>,
        io_args: &IOArgs<T, U, V>,
        emulator_type: EmulatorType,
    ) {
        // Serialize inputs
        let public_input_bytes = if let Some(input) = &io_args.public_input {
            to_allocvec(input).expect("Failed to serialize public input")
        } else {
            Vec::new()
        };

        let private_input_bytes = if let Some(input) = &io_args.private_input {
            to_allocvec(input).expect("Failed to serialize private input")
        } else {
            Vec::new()
        };

        // Serialize expected output
        let expected_output_bytes = if let Some(expected) = &io_args.expected_output {
            to_allocvec(expected).expect("Failed to serialize expected output")
        } else {
            Vec::new()
        };

        // Run emulation
        let (_, exit_code_bytes, output_bytes) = emulate(
            elfs,
            public_input_bytes,
            private_input_bytes,
            expected_output_bytes.len(),
            emulator_type,
        );

        // Parse and verify output
        let (exit_code, output) =
            parse_output::<V>(exit_code_bytes, output_bytes).expect("Failed to parse output");
        if let Some(expected) = &io_args.expected_output {
            assert_eq!(
                output.as_ref(),
                Some(expected),
                "Output mismatch: expected {:?}, got {:?}",
                expected,
                output
            );
            assert_eq!(
                Err(nexus_vm::error::VMError::VMExited(exit_code)),
                io_args.expected_result
            );
        }
    }

    /// Helper function to run test accross multiple emulators, multiple opt levels, and multiple inputs.
    fn test_example_multi<T: Input, U: Input, V: Output>(
        emulators: Vec<EmulatorType>,
        compile_flags: Vec<&str>,
        name: &str,
        io_args: Vec<IOArgs<T, U, V>>,
    ) {
        let elfs = compile_multi(name, &compile_flags);

        for emulator in &emulators {
            for io_arg in &io_args {
                emulate_wrapper(elfs.clone(), io_arg, emulator.clone());
            }
        }
    }

    #[test]
    #[serial]
    fn test_emulate_io() {
        test_example_multi(
            vec![EmulatorType::TwoPass],
            vec!["-C opt-level=3"],
            "../../examples/src/input_output",
            vec![IOArgs::<u32, u32, u32>::new(
                Some(3u32),
                Some(4u32),
                Some(12u32),
            )],
        );
    }

    #[test]
    #[serial]
    fn test_prove_io() {
        let elfs = compile_multi(
            &format!("../../examples/src/input_output"),
            &["-C opt-level=3"],
        );

        let public_input_bytes = to_allocvec(&512u32).unwrap();
        let private_input_bytes = to_allocvec(&2u32).unwrap();
        let mut expected_output_bytes = to_allocvec(&1024u32).unwrap();

        let padded_len = word_align!(expected_output_bytes.len());
        expected_output_bytes.resize(padded_len, 0);

        let (view, execution_trace) = k_trace(
            elfs[0].clone(),
            &[],
            &public_input_bytes,
            &private_input_bytes,
            K,
        )
        .expect("error generating trace");

        let output = view.get_public_output();
        let output_bytes = output.iter().map(|entry| entry.value).collect::<Vec<_>>();

        assert_eq!(
            output_bytes, expected_output_bytes,
            "Output bytes don't match expected output"
        );

        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_fact() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fact",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_fact() {
        let elfs = compile_multi("../../examples/src/fact", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_fib() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fib",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_fib() {
        let elfs = compile_multi("../../examples/src/fib", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_fib1000() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fib1000",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_prove_fib1000() {
        let elfs = compile_multi("../../examples/src/fib1000", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_main() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/main",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_main() {
        let elfs = compile_multi("../../examples/src/main", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_palindromes() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/palindromes",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_palindromes() {
        let elfs = compile_multi("../../examples/src/palindromes", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_gale_shapley() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/galeshapley",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_gale_shapley() {
        let elfs = compile_multi("../../examples/src/galeshapley", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_lambda_calculus() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/lambda_calculus",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_lambda_calculus() {
        let elfs = compile_multi("../../examples/src/lambda_calculus", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_keccak() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/keccak",
            IOArgs::<(), (), ()>::default_list(),
        );
    }

    #[test]
    #[serial]
    fn test_prove_keccak() {
        let elfs = compile_multi("../../examples/src/keccak", &["-C opt-level=3"]);
        let (view, execution_trace) =
            k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[serial]
    fn test_emulate_fail() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/fail",
            vec![IOArgs::<(), (), ()>::simple_panic()],
        );
    }

    #[test]
    #[serial]
    #[ignore]
    fn test_examples_all_opt_levels() {
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let compile_flags = vec![
            "-C opt-level=0",
            "-C opt-level=1",
            "-C opt-level=2",
            "-C opt-level=3",
        ];

        // Test simple examples.
        for example in EXAMPLES {
            let example_path = format!("../../examples/src/{}", example);
            let elfs = compile_multi(&example_path, &compile_flags);

            for emulator in &emulators {
                emulate_wrapper(
                    elfs.clone(),
                    &IOArgs::<(), (), ()>::default(),
                    emulator.clone(),
                );
            }
        }

        // Test fail example.
        let fail_path = "../../examples/src/fail";
        let fail_elfs = compile_multi(fail_path, &compile_flags);

        for emulator in &emulators {
            emulate_wrapper(
                fail_elfs.clone(),
                &IOArgs::<(), (), ()>::simple_panic(),
                emulator.clone(),
            );
        }
    }

    #[test]
    #[serial]
    fn test_emulate() {
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let compile_flags = vec!["-C opt-level=3"];
        let io_u32_elfs = compile_multi("io_u32", &compile_flags);
        let io_u64_elfs = compile_multi("io_u64", &compile_flags);
        let io_u128_elfs = compile_multi("io_u128", &compile_flags);

        for emulator in emulators {
            emulate_wrapper(
                io_u32_elfs.clone(),
                &IOArgs::<u32, (), u32>::new(Some(123u32), None, Some(123u32)),
                emulator.clone(),
            );

            emulate_wrapper(
                io_u64_elfs.clone(),
                &IOArgs::<u64, (), u64>::new(Some(1u64 << 32), None, Some(1u64 << 32)),
                emulator.clone(),
            );

            emulate_wrapper(
                io_u128_elfs.clone(),
                &IOArgs::<u128, (), u128>::new(
                    Some(332306998946228968225970211937533483u128),
                    None,
                    Some(332306998946228968225970211937533483u128),
                ),
                emulator.clone(),
            );
        }
    }

    #[test]
    #[serial]
    fn test_fib() {
        let inputs = vec![1u32, 10u32, 20u32];
        let outputs = vec![1u32, 34u32, 4181u32];
        let emulators = vec![
            EmulatorType::Harvard,
            EmulatorType::default_linear(),
            EmulatorType::TwoPass,
        ];
        let elfs = compile_multi("fib", &["-C opt-level=3"]);

        for (input, output) in inputs.iter().zip(outputs.iter()) {
            for emulator in emulators.clone() {
                emulate_wrapper(
                    elfs.clone(),
                    &IOArgs::<u32, (), u32>::new(Some(*input), None, Some(*output)),
                    emulator,
                );
            }
        }
    }

    #[test]
    #[serial]
    fn test_prove_synthetic_trace() {
        let log_size = 16;
        let blocks = program_trace(log_size);
        let (view, execution_trace) = k_trace_direct(&blocks, K).expect("error generating trace");
        let proof = prove(&execution_trace, &view).unwrap();
        verify(
            proof,
            view.get_program_memory(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn test_serialize_proofs() {
        for example in EXAMPLES {
            println!("Testing example: {}", example);
            let elfs = compile_multi(
                &format!("../../examples/src/{}", example),
                &["-C opt-level=3"],
            );
            let (view, execution_trace) =
                k_trace(elfs[0].clone(), &[], &[], &[], K).expect("error generating trace");
            let proof = prove(&execution_trace, &view).unwrap();
            let proof_path = format!("{}.proof", example);
            let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
            std::fs::write(&proof_path, &proof_bytes).expect("Failed to write proof to file");
            let deserialized_proof_bytes =
                postcard::from_bytes(&proof_bytes).expect("Failed to deserialize proof");
            verify(
                deserialized_proof_bytes,
                view.get_program_memory(),
                view.get_initial_memory(),
                view.get_exit_code(),
                view.get_public_output(),
            )
            .unwrap();
            verify(
                proof,
                view.get_program_memory(),
                view.get_initial_memory(),
                view.get_exit_code(),
                view.get_public_output(),
            )
            .unwrap();
        }
    }
}
