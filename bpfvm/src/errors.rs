use std::{array::TryFromSliceError, result};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Program len is bigger than limit (u16::MAX); {0:?}.")]
    ProgramTooLong(usize),
    #[error("Unsupported BPF instruction code (with flags): {0:?}.")]
    InvalidInstructionCode(u16),
    #[error("Unsupported BPF Instruction; {0:?}.")]
    UnsupportedInstruction(u16),
    #[error("Unsupported ABS offset type.")]
    UnsupportedDataOffset,
    #[error("Unknown BPF Instruction; {0:?}.")]
    UnknownInstruction(u16),
    #[error(transparent)]
    DataConversionError(#[from] TryFromSliceError),
}

pub type Result<T> = result::Result<T, Error>;
