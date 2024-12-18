/// In the guest context, there is nothing actually associated with the precompile other than the
/// convenience wrapper for emitting the instruction call.
pub struct DummyHash;

#[macro_export]
macro_rules! generate_instruction_caller {
    ($path:path) => {
        trait DummyHashCaller {
            fn hash(input: &[u8]) -> u32;
        }

        impl DummyHashCaller for $path {
            fn hash(input: &[u8]) -> u32 {
                let ptr = input.as_ptr() as u32;
                let len = input.len() as u32;
                Self::emit_instruction(ptr, len, 0)
            }
        }
    };
}
