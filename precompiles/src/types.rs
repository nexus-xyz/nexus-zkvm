use std::collections::HashMap;

/// The type corresponding to a function that precompile implementations can call to read from VM
/// memory. Returns the word at the given address, which must be word-aligned.
pub type MemReadFn = extern "C" fn(addr: u32) -> u32;

/// The type corresponding to a function that precompile implementations can call to write to VM
/// memory. Writes the word `value` to the given address, which must be word-aligned.
pub type MemWriteFn = extern "C" fn(addr: u32, value: u32);

/// The function signature for the precompile's implementation found in its shared library
/// distribution. The implementation may ignore the values of the `rs1` and `rs2` arguments if they
/// are not used.
///
/// The return value should be a 64 bit field `high||low`, where `high` and `low` are each 32 bit
/// fields, indexed here by bits. The VM should interpret these return values as follows:
/// - `high[0] == 0` and `high[1] == 0`: The precompile executed successfully, but `rd` must not be
///   updated.
/// - `high[0] == 0` and `high[1] == 1`: The precompile executed successfully, and `low` must be
///   written to `rd`.
/// - `high[0] == 1`: The precompile encountered an error whose code is specified by `low`. The
///   precompile's author should make available a list of error codes and their meanings. In the
///   future, we can include these mappings in the precompile manifest.
pub type EvalFn =
    extern "C" fn(rs1: u32, rs2: u32, mem_read: MemReadFn, mem_write: MemWriteFn) -> u64;

pub struct PrecompileMetadata {
    _author: String,
    _name: String,
    _version_major: u32,
    _version_minor: u32,
    _version_patch: u32,
    _digest: [u8; 32],
    _error_map: HashMap<u32, String>,
}

/// A precompile, loaded and useful to the VM for execution and proving. The VM's runtime mostly
/// cares about being able to call `eval`, and the prover cares about being able to access the
/// precompile's circuits.
pub trait ProvablePrecompile {
    fn circuit(&self);
}
