mod eval;
mod traits;

pub(crate) use traits::{builtin::BuiltInComponent, erased::MachineComponent};

#[cfg(test)]
pub(crate) mod test_utils;
