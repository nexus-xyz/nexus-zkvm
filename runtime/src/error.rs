#[derive(Debug, PartialEq)]
pub enum NexusRTError {
    InputLengthOverflow(usize),

    OutputLengthOverflow(usize),

    MemoryError(postcard::Error),
}

impl From<postcard::Error> for NexusRTError {
    fn from(e: postcard::Error) -> Self {
        NexusRTError::MemoryError(e)
    }
}
