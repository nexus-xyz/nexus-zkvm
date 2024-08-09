use sysinfo::System;

/// Determine the optimal number of VM instructions to pack per recursion step
/// based on the total available system memory.
/// # Returns
/// A power of 2 between 2 and 256, inclusive.
pub fn determine_k() -> usize {
    let total_mem = System::new_all().total_memory() >> 30;
    match total_mem {
        0..2 => 2,
        2..4 => 4,
        4..8 => 8,
        8..16 => 16,
        16..32 => 32,
        32..64 => 64,
        64..128 => 128,
        _ => 256,
    }
}
