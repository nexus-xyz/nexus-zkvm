pub mod emulator;

#[cfg(test)]
use nexus_vm::elf::ElfFile;
#[cfg(test)]
use serde::{de::DeserializeOwned, Serialize};

#[cfg(test)]
use crate::emulator::*;
#[cfg(test)]
use postcard::to_allocvec;

#[cfg(test)]
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
#[cfg(test)]
mod test {
    use super::*;
    use serial_test::serial;
    trait Input: Serialize + std::fmt::Debug + Clone {}
    impl<T> Input for T where T: Serialize + std::fmt::Debug + Clone {}
    trait Output: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}
    impl<T> Output for T where T: Serialize + DeserializeOwned + std::fmt::Debug + PartialEq + Clone {}

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
    fn test_fact_example() {
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
    fn test_fib_example() {
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
    fn test_fib1000_example() {
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
    fn test_main_example() {
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
    fn test_palindromes_example() {
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
    fn test_galeshapley_example() {
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
    fn test_lambda_calculus_example() {
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
    fn test_fail_example() {
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
    fn test_input_output_example() {
        test_example_multi(
            vec![
                EmulatorType::Harvard,
                EmulatorType::default_linear(),
                EmulatorType::TwoPass,
            ],
            vec!["-C opt-level=3"],
            "../../examples/src/input_output",
            vec![
                IOArgs::<u32, u32, u32>::new(Some(3u32), Some(4u32), Some(12u32)),
                IOArgs::<u32, u32, u32>::new(Some(4u32), Some(0u32), Some(0u32)),
                IOArgs::<u32, u32, u32>::new(Some(1_048_576u32), Some(4u32), Some(4_194_304u32)),
            ],
        );
    }

    #[test]
    #[serial]
    fn test_keccak_example() {
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
        let examples = vec![
            "fact",
            "fib",
            "fib1000",
            "main",
            "palindromes",
            "galeshapley",
            "lambda_calculus",
            "keccak",
        ];

        // Test simple examples.
        for example in examples {
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
}
