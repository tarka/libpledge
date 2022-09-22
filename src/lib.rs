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

mod errors;
mod promises;
mod seccomp;

// Currently maps 1-1 to SeccompAction
pub enum ViolationAction {
    /// Allows syscall.
    Allow,
    /// Returns from syscall with specified error number.
    Errno(u32),
    /// Kills calling thread.
    KillThread,
    /// Kills calling process.
    KillProcess,
    /// Allows syscall after logging it.
    Log,
    /// Notifies tracing process of the caller with respective number.
    Trace(u32),
    /// Sends `SIGSYS` to the calling process.
    Trap,
}

pub use promises::Promise;
pub use seccomp::pledge;
pub use seccomp::pledge_override;

pub use errors::Error;
pub use errors::Result;
