use super::{Buffer, Permutation};

/// Updates the keccak state stored at `addr`. The macro can only be invoked through the public interface.
macro_rules! keccakf_call {
    ($addr:expr) => {
        unsafe {
            core::arch::asm!(
                ".insn s 0b1011010, 0b000, x0, 0({0})",
                in(reg) $addr,
            )
        }
    };
}

pub fn keccakf(state: &mut [u64; 25]) {
    let state_ptr = state as *mut _;
    keccakf_call!(state_ptr);
}

pub struct KeccakF;

impl Permutation for KeccakF {
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}
