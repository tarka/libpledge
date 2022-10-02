/*
 * Copyright © 2022, Steve Smith <tarkasteve@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

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
    #[error("Unsupported Return value; {0:?}.")]
    UnsupportedReturn(u32),
    #[error("Unsupported ABS offset type.")]
    UnsupportedDataOffset,
    #[error("Unknown BPF Instruction; {0:?}.")]
    UnknownInstruction(u16),
    #[error(transparent)]
    DataConversionError(#[from] TryFromSliceError),
}

pub type Result<T> = result::Result<T, Error>;
