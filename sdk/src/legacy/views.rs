use crate::error::IOError;
use crate::legacy::traits::LegacyViewable;
use serde::de::DeserializeOwned;

/// A view capturing the unchecked output of a zkVM execution.
///
/// By _unchecked_, it is meant that although the zkVM proves that the guest program correctly wrote to the output tape, there is no cryptographic
/// guarantee that the return of `output()` as accessed by the host program contains the same values that were written.
///
/// Support for checked views is under active development.
#[derive(Debug, Default)]
pub struct UncheckedView {
    pub(crate) out: Vec<u8>,
    pub(crate) logs: Vec<String>,
}

impl LegacyViewable for UncheckedView {
    fn output<U: DeserializeOwned>(&self) -> Result<U, IOError> {
        Ok(postcard::from_bytes::<U>(self.out.as_slice())?)
    }

    fn logs(&self) -> &Vec<String> {
        &self.logs
    }
}
