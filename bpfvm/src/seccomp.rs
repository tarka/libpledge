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
pub enum SeccompReturn {
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

impl TryFrom<u32> for SeccompReturn {
    type Error = Error;
    fn try_from(ret: u32) -> Result<Self> {
        let action = ret & SECCOMP_RET_ACTION_FULL;
        let val = ret & SECCOMP_RET_DATA;
        use SeccompReturn::*;

        match action {
            SECCOMP_RET_KILL_PROCESS => Ok(KillProcess),
            SECCOMP_RET_KILL_THREAD  => Ok(KillThread),
            SECCOMP_RET_TRAP         => Ok(Trap),
            SECCOMP_RET_ERRNO        => Ok(Errno(val)),
            SECCOMP_RET_TRACE        => Ok(Trace(val)),
            SECCOMP_RET_LOG          => Ok(Log),
            SECCOMP_RET_ALLOW        => Ok(Allow),
            _ => Err(Error::UnsupportedReturn(ret)),
        }
    }

}

pub enum FieldOffset {
    Syscall,
    Arch,
    InstrPointerLower,
    InstrPointerUpper,
    ArgLower(u32),
    ArgUpper(u32),
}

impl FieldOffset {
    pub fn offset(&self) -> u32 {
        use FieldOffset::*;
        match self {
            Syscall => 0,
            Arch => 4,
            InstrPointerLower => 8,
            InstrPointerUpper => 12,
            ArgLower(arg) => (4 + 4 + 8) + (arg * 8),
            ArgUpper(arg) => (4 + 4 + 8) + (arg * 8) + 4,
        }
    }
}


pub fn run_seccomp(prog: BPFProg, syscall: libc::seccomp_data) -> Result<SeccompReturn> {
    let code = BpfVM::new(prog)?.run(any_to_data(&syscall))?;
    SeccompReturn::try_from(code)
}


#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use test_log;
    use crate::{any_to_data, BpfVM};

    #[test_log::test]
    fn test_offsets() {
        use crate::bpf::JmpOp::*;
        use crate::bpf::Mode::*;
        use crate::bpf::Src::*;
        use crate::asm::Operation::*;
        use crate::asm::compile;
        use FieldOffset::*;

        let asm = vec![
            Load(ABS, Syscall.offset()),
            Jump(JEQ, 0xffffffff, None, Some("FAIL")),
            Load(ABS, Arch.offset()),
            Jump(JEQ, 0xeeeeeeee, None, Some("FAIL")),
            Load(ABS, InstrPointerUpper.offset()),
            Jump(JEQ, 0xcccccccc, None, Some("FAIL")),
            Load(ABS, InstrPointerLower.offset()),
            Jump(JEQ, 0xdddddddd, None, Some("FAIL")),

            Load(ABS, ArgLower(0).offset()),
            Jump(JEQ, 0x11111111, None, Some("FAIL")),
            Load(ABS, ArgUpper(0).offset()),
            Jump(JEQ, 0, None, Some("FAIL")),

            Load(ABS, ArgLower(1).offset()),
            Jump(JEQ, 0x22222222, None, Some("FAIL")),
            Load(ABS, ArgUpper(2).offset()),
            Jump(JEQ, 0x33333333, None, Some("FAIL")),
            Load(ABS, ArgLower(2).offset()),
            Jump(JEQ, 0x44444444, None, Some("FAIL")),
            Load(ABS, ArgLower(3).offset()),
            Jump(JEQ, 0x55555555, None, Some("FAIL")),
            Load(ABS, ArgUpper(4).offset()),
            Jump(JEQ, 0x66666666, None, Some("FAIL")),
            Load(ABS, ArgLower(4).offset()),
            Jump(JEQ, 0x77777777, None, Some("FAIL")),
            Load(ABS, ArgLower(5).offset()),
            Jump(JEQ, 0x88888888, None, Some("FAIL")),

            Label("ALLOW"),
            Return(Const, 0),

            Label("FAIL"),
            Return(Const, 99),
        ];
        let prog = compile(&asm).unwrap();
        let mut vm = BpfVM::new(prog).unwrap();

        let sc_data = libc::seccomp_data {
            nr: -1,
            arch: 0xeeeeeeee,
            instruction_pointer: 0xccccccccdddddddd,
            args: [
                0x11111111,
                0x22222222,
                0x3333333344444444,
                0x55555555,
                0x6666666677777777,
                0x88888888,
            ],
        };
        let data = any_to_data(&sc_data);
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0);
    }

}
