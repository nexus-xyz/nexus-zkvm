/// In the guest context, there is nothing actually associated with the precompile other than the
/// convenience wrapper for emitting the instruction call.
pub struct DummyDiv;

#[macro_export]
macro_rules! generate_instruction_caller {
    ($path:path) => {
        trait DummyDivCaller {
            fn div(dividend: u32, divisor: u32) -> u32;
        }

        impl DummyDivCaller for $path {
            fn div(dividend: u32, divisor: u32) -> u32 {
                Self::emit_instruction(dividend, divisor, 0)
            }
        }
    };
}
