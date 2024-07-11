use crate::error::TapeError;
use crate::traits::Viewable;
use serde::de::DeserializeOwned;

/// A view capturing the unchecked output of a zkVM execution.
///
/// By _unchecked_, it is meant that although the zkVM proves that the
/// guest program correctly wrote to the output tape, there is not any
/// guarantee that the return of `output()` are those values that were
/// written.
///
/// Support for checked views is under active development.
pub struct UncheckedView {
    pub(crate) output: Vec<u8>,
    pub(crate) logs: Vec<String>,
}

impl Viewable for UncheckedView {
    fn output<U: DeserializeOwned>(&self) -> Result<U, TapeError> {
        Ok(postcard::from_bytes::<U>(self.output.as_slice())?)
    }

    fn logs(&self) -> &Vec<String> {
        &self.logs
    }
}
