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


use crate::{BPFProg, BpfVM, any_to_data};
use crate::errors::{Error, Result};


// See <linux-src>/include/uapi/linux/audit.h
pub const AUDIT_ARCH_64BIT: u32 = 0x80000000;
pub const AUDIT_ARCH_LE: u32 = 0x40000000;
pub const EM_X86_64: u32 = 62;
pub const EM_AARCH64: u32 = 183;

pub const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
pub const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;


// See /usr/include/linux/seccomp.h
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000; /* kill the process */
pub const SECCOMP_RET_KILL_THREAD : u32 = 0x00000000; /* kill the thread */
pub const SECCOMP_RET_KILL        : u32 = SECCOMP_RET_KILL_THREAD;
pub const SECCOMP_RET_TRAP        : u32 = 0x00030000; /* disallow and force a SIGSYS */
pub const SECCOMP_RET_ERRNO       : u32 = 0x00050000; /* returns an errno */
pub const SECCOMP_RET_USER_NOTIF  : u32 = 0x7fc00000; /* notifies userspace */
pub const SECCOMP_RET_TRACE       : u32 = 0x7ff00000; /* pass to a tracer or disallow */
pub const SECCOMP_RET_LOG         : u32 = 0x7ffc0000; /* allow after logging */
pub const SECCOMP_RET_ALLOW       : u32 = 0x7fff0000; /* allow */

/* Masks for the return value sections. */
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff0000;
pub const SECCOMP_RET_ACTION     : u32 = 0x7fff0000;
pub const SECCOMP_RET_DATA       : u32 = 0x0000ffff;


// Currently maps 1-1 to SeccompAction
#[derive(Eq, PartialEq, Debug)]
pub enum Return {
    /// Kill the process.
    KillProcess,
    /// Kill the thread.
    KillThread,
    /// Sends `SIGSYS` to the calling process.
    Trap,
    /// Returns from syscall with specified error number.
    Errno(u32),
    /// Notifies tracing process of the caller with respective number.
    Trace(u32),
    /// Allows syscall after logging it.
    Log,
    /// Allows syscall.
    Allow,
}

impl TryFrom<u32> for Return {
    type Error = Error;
    fn try_from(ret: u32) -> Result<Self> {
        let action = ret & SECCOMP_RET_ACTION_FULL;
        let val = ret & SECCOMP_RET_DATA;

        match action {
            SECCOMP_RET_KILL_PROCESS => Ok(Return::KillProcess),
            SECCOMP_RET_KILL_THREAD  => Ok(Return::KillThread),
            SECCOMP_RET_TRAP         => Ok(Return::Trap),
            SECCOMP_RET_ERRNO        => Ok(Return::Errno(val)),
            SECCOMP_RET_TRACE        => Ok(Return::Trace(val)),
            SECCOMP_RET_LOG          => Ok(Return::Log),
            SECCOMP_RET_ALLOW        => Ok(Return::Allow),
            _ => Err(Error::UnsupportedReturn(ret)),
        }
    }

}



pub fn run_seccomp(prog: BPFProg, syscall: libc::seccomp_data) -> Result<Return> {
    let code = BpfVM::new(prog)?.run(any_to_data(&syscall))?;
    Return::try_from(code)
}
