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

use std::{env::consts::ARCH, process};
use libc;
use bpfvm::{
    asm::{compile, Operation::*},
    bpf::{AluOp::*, JmpOp::*, Mode::*, Src::*},
    seccomp::{AUDIT_ARCH_X86_64, FieldOffset::*, SeccompReturn},
};
use crate::{
    errors::{Error, Result},
    promises::{Filtered::{self, *}, Promise, PROMISES},
    ViolationAction,
};

pub type WhitelistFrag = Vec<libc::sock_filter>;

const __O_TMPFILE: i32 = 0o20000000;


macro_rules! syscall_check {
    ( $syscall:expr, $($el:expr), *) =>
        ([
            Load(ABS, Syscall.offset()),
            Jump(JEQ, $syscall as u32, None, Some("NEXT_FILTER")),
            $($el,)*
            Return(Const, SeccompReturn::Allow.into()),
            Label("NEXT_FILTER"),
        ])
}

fn whitelist_syscall(syscall: libc::c_long) -> Result<WhitelistFrag> {
    // FIXME: Hack to simplify the macro. There's probably a better way.
    let asm = syscall_check!(syscall,);
    Ok(compile(&asm)?)
}

// The second argument of fcntl() must be one of:
//
//   - F_DUPFD (0)
//   - F_GETFD (1)
//   - F_SETFD (2)
//   - F_GETFL (3)
//   - F_SETFL (4)
//   - F_DUPFD_CLOEXEC (1030)
//
fn fcntl_stdio() -> Result<WhitelistFrag> {
    let asm = syscall_check!(
        libc::SYS_fcntl,
        Load(ABS, ArgLower(1).offset()),
        Jump(JEQ, libc::F_DUPFD_CLOEXEC as u32, Some("Allow"), None),
        Jump(JGT, 4, Some("NEXT_FILTER"), None),
        Label("Allow"),
        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// The flags parameter of mmap() must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
fn mmap_noexec() -> Result<WhitelistFrag> {
    let mask = libc::MAP_LOCKED | libc::MAP_NONBLOCK | libc::MAP_HUGETLB;
    let asm = syscall_check!(
        libc::SYS_mmap,

        Load(ABS, ArgLower(3).offset()),
        Alu(AND, Const, mask as u32),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),

        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// The prot parameter of mprotect() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
fn mprotect_noexec() -> Result<WhitelistFrag> {
    let mask = !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_NONE);
    let asm = syscall_check!(
        libc::SYS_mprotect,

        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, mask as u32),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),

        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// The sockaddr parameter of sendto() must be
//
//   - NULL
//
fn sendto_addrless() -> Result<WhitelistFrag> {
    let asm = syscall_check!(
        libc::SYS_sendto,

        Load(ABS, ArgLower(4).offset()),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),
        Load(ABS, ArgUpper(4).offset()),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),

        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// // The second argument of ioctl() must be one of:
// //
// //   - FIONREAD (0x541b)
// //   - FIONBIO  (0x5421)
// //   - FIOCLEX  (0x5451)
// //   - FIONCLEX (0x5450)
// //
// fn ioctl_restrict() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_ioctl,
//         vec![
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::FIONREAD,
//             )?])?,
//             Rule::new(vec![Cond::new(1, ArgLen::Dword, CmpOp::Eq, libc::FIONBIO)?])?,
//             Rule::new(vec![Cond::new(1, ArgLen::Dword, CmpOp::Eq, libc::FIOCLEX)?])?,
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::FIONCLEX,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }

// // The first argument of kill() must be
// //
// //   - getpid()
// //
// fn kill_self() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_kill,
//         vec![Rule::new(vec![Cond::new(
//             0,
//             ArgLen::Dword,
//             CmpOp::Eq,
//             process::id() as u64,
//         )?])?],
//     );
//     Ok(wl)
// }

// // The first argument of tkill() must be
// //
// //   - gettid()
// //
// fn tkill_self() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_tkill,
//         vec![Rule::new(vec![Cond::new(
//             0,
//             ArgLen::Dword,
//             CmpOp::Eq,
//             unsafe { libc::gettid() } as u64,
//         )?])?],
//     );
//     Ok(wl)
// }

// // The first parameter of prctl() can be any of
// //
// //   - PR_SET_NAME         (15)
// //   - PR_GET_NAME         (16)
// //   - PR_GET_SECCOMP      (21)
// //   - PR_SET_SECCOMP      (22)
// //   - PR_SET_NO_NEW_PRIVS (38)
// //   - PR_CAPBSET_READ     (23)
// //   - PR_CAPBSET_DROP     (24)
// //
// fn prctl_stdio() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_prctl,
//         vec![
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_SET_NAME as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_GET_NAME as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_GET_SECCOMP as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_SET_SECCOMP as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_SET_NO_NEW_PRIVS as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_CAPBSET_READ as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 0,
//                 ArgLen::Dword,
//                 CmpOp::Eq,
//                 libc::PR_CAPBSET_DROP as u64,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }

// // The first argument of sys_clone_linux() must have:
// //
// //   - CLONE_VM       (0x00000100)
// //   - CLONE_FS       (0x00000200)
// //   - CLONE_FILES    (0x00000400)
// //   - CLONE_THREAD   (0x00010000)
// //   - CLONE_SIGHAND  (0x00000800)
// //
// // The first argument of sys_clone_linux() must NOT have:
// //
// //   - CLONE_NEWNS    (0x00020000)
// //   - CLONE_PTRACE   (0x00002000)
// //   - CLONE_UNTRACED (0x00800000)
// //
// fn clone_thread() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_clone,
//         vec![Rule::new(vec![
//             Cond::new(0, ArgLen::Dword, CmpOp::MaskedEq(0x00010f00), 0x00010f00)?,
//             Cond::new(0, ArgLen::Dword, CmpOp::MaskedEq(0x00822000), 0)?,
//         ])?],
//     );
//     Ok(wl)
// }

// // The new_limit parameter of prlimit() must be
// //
// //   - NULL (0)
// //
// fn prlimit64_stdio() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_prlimit64,
//         vec![Rule::new(vec![
//             Cond::new(2, ArgLen::Qword, CmpOp::Eq, 0)?
//         ])?],
//     );
//     Ok(wl)
// }

// // The open() system call is permitted only when
// //
// //   - (flags & O_ACCMODE) == O_RDONLY
// //
// // The flags parameter of open() must not have:
// //
// //   - O_CREAT     (000000100)
// //   - O_TRUNC     (000001000)
// //   - __O_TMPFILE (020000000)
// //
// fn open_readonly() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_open,
//         vec![
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq(libc::O_ACCMODE as u64),
//                 libc::O_RDONLY as u64,
//             )?])?,
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq(0o020001100),
//                 0,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }

// The openat() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_RDONLY
//
// The flags parameter of open() must not have:
//
//   - O_CREAT     (000000100)
//   - O_TRUNC     (000001000)
//   - __O_TMPFILE (020000000)
//
fn openat_readonly() -> Result<WhitelistFrag> {
    let mask = libc::O_CREAT | libc::O_TRUNC | __O_TMPFILE;
    let asm = syscall_check!(
        libc::SYS_openat,

        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, libc::O_ACCMODE as u32),
        Jump(JEQ, libc::O_RDONLY as u32, None, Some("NEXT_FILTER")),

        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, mask as u32),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),

        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}


// // The open() system call is permitted only when
// //
// //   - (flags & O_ACCMODE) == O_WRONLY
// //   - (flags & O_ACCMODE) == O_RDWR
// //
// // The open() flags parameter must not contain
// //
// //   - O_CREAT     (000000100)
// //   - __O_TMPFILE (020000000)
// //
// fn open_writeonly() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_open,
//         vec![
//             Rule::new(vec![
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(libc::O_ACCMODE as u64),
//                     libc::O_WRONLY as u64,
//                 )?,
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(0o020000100),
//                     0,
//                 )?

//             ])?,
//             Rule::new(vec![
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(libc::O_ACCMODE as u64),
//                     libc::O_RDWR as u64,
//                 )?,
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(0o020000100),
//                     0,
//                 )?
//             ])?,
//         ],
//     );
//     Ok(wl)
// }


// The openat() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_WRONLY
//   - (flags & O_ACCMODE) == O_RDWR
//
// The open() flags parameter must not contain
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
fn openat_writeonly() -> Result<WhitelistFrag> {
    let mask = libc::O_CREAT | __O_TMPFILE;
    let asm = syscall_check!(
        libc::SYS_openat,

        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, libc::O_ACCMODE as u32),
        Jump(JEQ, libc::O_WRONLY as u32, Some("FLAG_CHECK"), None),
        Jump(JEQ, libc::O_RDWR as u32, None, Some("NEXT_FILTER")),

        Label("FLAG_CHECK"),
        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, mask as u32),
        Jump(JEQ, 0, None, Some("NEXT_FILTER")),

        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// // The mode parameter of chmod() can't have the following:
// //
// //   - S_ISVTX (01000 sticky)
// //   - S_ISGID (02000 setgid)
// //   - S_ISUID (04000 setuid)
// //
// fn chmod_nobits() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_chmod,
//         vec![
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                 0,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }


// // The mode parameter of fchmod() can't have the following:
// //
// //   - S_ISVTX (01000 sticky)
// //   - S_ISGID (02000 setgid)
// //   - S_ISUID (04000 setuid)
// //
// fn fchmod_nobits() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_fchmod,
//         vec![
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                 0,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }


// // The mode parameter of fchmodat() can't have the following:
// //
// //   - S_ISVTX (01000 sticky)
// //   - S_ISGID (02000 setgid)
// //   - S_ISUID (04000 setuid)
// //
// fn fchmodat_nobits() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_fchmod,
//         vec![
//             Rule::new(vec![Cond::new(
//                 2,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                 0,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }


// // If the flags parameter of open() has one of:
// //
// //   - O_CREAT     (000000100)
// //   - __O_TMPFILE (020000000)
// //
// // Then the mode parameter must not have:
// //
// //   - S_ISVTX (01000 sticky)
// //   - S_ISGID (02000 setgid)
// //   - S_ISUID (04000 setuid)
// //
// fn open_createonly() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_open,
//         vec![
//             Rule::new(vec![
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(libc::O_CREAT as u64),
//                     libc::O_CREAT as u64,
//                 )?,
//                 Cond::new(
//                     2,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                     0,
//                 )?,
//             ])?,
//             Rule::new(vec![
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq(0o020200000),
//                     0o020200000,
//                 )?,
//                 Cond::new(
//                     2,
//                     ArgLen::Dword,
//                     CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                     0,
//                 )?,
//             ])?,
//         ],
//     );
//     Ok(wl)
// }


// If the flags parameter of openat() has one of:
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
fn openat_createonly() -> Result<WhitelistFrag> {
    let mmask = libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID;
    let asm = syscall_check!(
        libc::SYS_openat,
        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, libc::O_CREAT as u32),
        Jump(JEQ, libc::O_CREAT as u32, Some("FLAG_CHECK"), None),
        Load(ABS, ArgLower(2).offset()),
        Alu(AND, Const, __O_TMPFILE as u32),
        Jump(JEQ, __O_TMPFILE as u32, Some("FLAG_CHECK"), Some("ALLOW")),

        Label("FLAG_CHECK"),
        Load(ABS, ArgLower(3).offset()),
        Alu(AND, Const, mmask as u32),
        Jump(JEQ, 0, Some("ALLOW"), Some("NEXT_FILTER")),

        Label("ALLOW"),
        Return(Const, SeccompReturn::Allow.into())
    );
    Ok(compile(&asm)?)
}

// // Then the mode parameter must not have:
// //
// //   - S_ISVTX (01000 sticky)
// //   - S_ISGID (02000 setgid)
// //   - S_ISUID (04000 setuid)
// //
// fn create_restrict() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_creat,
//         vec![
//             Rule::new(vec![Cond::new(
//                 1,
//                 ArgLen::Dword,
//                 CmpOp::MaskedEq((libc::S_ISVTX | libc::S_ISGID | libc::S_ISUID) as u64),
//                 0,
//             )?])?,
//         ],
//     );
//     Ok(wl)
// }


// // The second argument of fcntl() must be one of:
// //
// //   - F_GETLK (5)
// //   - F_SETLK (6)
// //   - F_SETLKW (7)
// //
// fn fcntl_lock() -> Result<WhitelistFrag> {
//     let wl = (
//         libc::SYS_fcntl,
//         vec![
//             Rule::new(vec![
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::Ge,
//                     5,
//                 )?,
//                 Cond::new(
//                     1,
//                     ArgLen::Dword,
//                     CmpOp::Le,
//                     7,
//                 )?,
//             ])?,
//         ]
//     );
//     Ok(wl)
// }


// // The family parameter of socket() must be one of:
// //
// //   - AF_INET  (0x02)
// //   - AF_INET6 (0x0a)
// //
// // The type parameter of socket() will ignore:
// //
// //   - SOCK_CLOEXEC  (0x80000)
// //   - SOCK_NONBLOCK (0x00800)
// //
// // The type parameter of socket() must be one of:
// //
// //   - SOCK_STREAM (0x01)
// //   - SOCK_DGRAM  (0x02)
// //
// // The protocol parameter of socket() must be one of:
// //
// //   - 0
// //   - IPPROTO_ICMP (0x01)
// //   - IPPROTO_TCP  (0x06)
// //   - IPPROTO_UDP  (0x11)
// //
// // static privileged void AllowSocketInet(struct Filter *f) {
// //   static const struct sock_filter fragment[] = {
// //       /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_linux_socket, 0, 15 - 1),
// //       /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
// //       /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 1, 0),
// //       /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0a, 0, 14 - 4),
// //       /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
// //       /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
// //       /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 1, 0),
// //       /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 0, 14 - 8),
// //       /* L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
// //       /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x00, 3, 0),
// //       /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 2, 0),
// //       /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 1, 0),
// //       /*L12*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 1),
// //       /*L13*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
// //       /*L14*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
// //       /*L15*/ /* next filter */
// //   };
// //   AppendFilter(f, PLEDGE(fragment));
// // }
// fn socket_inet() -> Result<WhitelistFrag> {
//     Ok((0, Vec::new()))
// }

// fn ioctl_int() -> Result<WhitelistFrag> {
//     Ok((0, Vec::new()))
// }

// fn getsockopt_restrict() -> Result<WhitelistFrag> {
//     Ok((0, Vec::new()))
// }

// fn setsockopt_restrict() -> Result<WhitelistFrag> {
//     Ok((0, Vec::new()))
// }

fn bpf_header() -> Result<WhitelistFrag> {
    // FIXME: Move default promises here?
    let asm = [
        Load(ABS, Arch.offset()),
        Jump(JEQ, AUDIT_ARCH_X86_64, Some("START"), None),
        Return(Const, SeccompReturn::KillProcess.into()),
        Label("START"),
    ];

    Ok(compile(&asm)?)
}

fn bpf_footer(violation: ViolationAction) -> Result<WhitelistFrag> {
    let retval = violation.into();
    let asm = [Return(Const, retval)];
    Ok(compile(&asm)?)
}


fn oath_to_bpf(filter: &Filtered) -> Result<WhitelistFrag> {
    match filter {
        Whitelist(syscall) => whitelist_syscall(*syscall),
        FcntlStdio => fcntl_stdio(),
        MmapNoexec => mmap_noexec(),
        MprotectNoexec => mprotect_noexec(),
        SendtoAddrless => sendto_addrless(),
        // IoctlRestrict => ioctl_restrict(),
        // KillSelf => kill_self(),
        // TkillSelf => tkill_self(),
        // PrctlStdio => prctl_stdio(),
        // CloneThread => clone_thread(),
        // Prlimit64Stdio => prlimit64_stdio(),
        // OpenReadonly => open_readonly(),
        OpenatReadonly => openat_readonly(),
        // OpenWriteonly => open_writeonly(),
        OpenatWriteonly => openat_writeonly(),
        // ChmodNobits => chmod_nobits(),
        // FchmodNobits => fchmod_nobits(),
        // FchmodatNobits => fchmodat_nobits(),
        // OpenCreateonly => open_createonly(),
        OpenatCreateonly => openat_createonly(),
        // CreatRestrict => create_restrict(),
        // FcntlLock => fcntl_lock(),
        // SocketInet => socket_inet(),
        // IoctlInet => ioctl_int(),
        // GetsockoptRestrict => getsockopt_restrict(),
        // SetsockoptRestrict => setsockopt_restrict(),

    }
}


pub fn pledge(promises: Vec<Promise>) -> Result<()> {
    pledge_override(promises, ViolationAction::KillProcess)
}


fn promises_to_prog(promises: Vec<Promise>, violation: ViolationAction) -> Result<WhitelistFrag> {
    // Convert all promises into filter specs (lists of allowed
    // syscalls & params).
    let defaults = vec![Promise::Default];
    let filters = defaults
        .into_iter()
        .chain(promises.into_iter())
        .map(|p| PROMISES.get(&p).ok_or(Error::UndefinedPromise(p)))
        .collect::<Result<Vec<&Vec<Filtered>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<&Filtered>>();

    // Convert filters to seccomp BPF
    let whitelist = filters
        .into_iter()
        .map(oath_to_bpf)
        .collect::<Result<Vec<WhitelistFrag>>>()?;

    // Assemble parts
    let header = [bpf_header()?];
    let footer = [bpf_footer(violation)?];
    let prog = header
        .into_iter()
        .chain(whitelist)
        .chain(footer.into_iter())
        .flatten()
        .collect::<WhitelistFrag>();

    Ok(prog)
}

pub fn pledge_override(promises: Vec<Promise>, violation: ViolationAction) -> Result<()> {
    // Coerce the sock_filter list into a C-like pointer. The kernel
    // copies the program, so we don't need to worry about lifetimes.
    let mut bpf_prog = promises_to_prog(promises, violation)?;
    let prog_ref = &mut bpf_prog;

    let bpf_prog = libc::sock_fprog {
        len: prog_ref.len() as u16,
        filter: prog_ref.as_mut_ptr(),
    };
    let bpf_prog_ptr = &bpf_prog as *const libc::sock_fprog;

    // Disable new privs, and load seccomp...
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(Error::SysErr(std::io::Error::last_os_error()));
    }

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            bpf_prog_ptr,
        )
    };
    if ret != 0 {
        return Err(Error::SysErr(std::io::Error::last_os_error()));
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Promise::*, ViolationAction};
    use bpfvm::seccomp::*;
    use libc::seccomp_data;
    use test_log;

    fn syscall(call: i64, args: [u64; 6]) -> seccomp_data {
        libc::seccomp_data {
            nr: call as i32,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args: args
        }
    }

    #[test_log::test]
    fn stdio_personality_errno() {
        let prog = promises_to_prog(vec![StdIO], ViolationAction::Errno(999)).unwrap();
        let sc_data = syscall(libc::SYS_personality, [0;6]);

        let ret = run_seccomp(&prog, sc_data).unwrap();

        assert!(ret == SeccompReturn::Errno(999), "Failed, ret = 0x{:?}", ret);
    }

    #[test_log::test]
    fn stdio_personality_killed() {
        let prog = promises_to_prog(vec![StdIO], ViolationAction::KillProcess).unwrap();
        let sc_data = syscall(libc::SYS_personality, [0;6]);

        let ret = run_seccomp(&prog, sc_data).unwrap();

        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);
    }


    #[test_log::test]
    fn stdio_time_ok() {
        let prog = promises_to_prog(vec![StdIO], ViolationAction::KillProcess).unwrap();
        let sc_data = syscall(libc::SYS_gettimeofday, [0;6]);

        let ret = run_seccomp(&prog, sc_data).unwrap();

        assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);
    }


    #[test_log::test]
    fn rust_file_open() {
        // openat(AT_FDCWD, "file.txt", O_WRONLY|O_CREAT|O_CLOEXEC, 0666) = 257
        let prog = promises_to_prog(vec![StdIO, CPath], ViolationAction::KillProcess).unwrap();

        let sc_data = syscall(libc::SYS_openat, [0, 0, (libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC) as u64, 0o666, 0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);
    }

    #[test_log::test]
    fn fcntl_stdio() {
        let prog = promises_to_prog(vec![StdIO], ViolationAction::KillProcess).unwrap();

        let sc_data = syscall(libc::SYS_fcntl, [42, libc::F_DUPFD_CLOEXEC as u64, 0, 0, 0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);

        let sc_data = syscall(libc::SYS_fcntl, [42, libc::F_SETFD as u64, 0, 0, 0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);

        let sc_data = syscall(libc::SYS_fcntl, [42, libc::F_NOTIFY as u64, 0, 0, 0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);
    }


    #[test_log::test]
    fn no_fcntl_lock() {
        let prog = promises_to_prog(vec![StdIO, CPath],
                                    ViolationAction::KillProcess).unwrap();
        let sc_data = syscall(libc::SYS_fcntl, [42, libc::F_GETLK as u64, 0, 0, 0, 0]);

        let ret = run_seccomp(&prog, sc_data).unwrap();

        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);
    }

    #[test_log::test]
    fn sendto_addr() {
        let prog = promises_to_prog(vec![StdIO], ViolationAction::KillProcess).unwrap();

        let sc_data = syscall(libc::SYS_sendto, [0, 0, 0, 0, !0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);

        let sc_data = syscall(libc::SYS_sendto, [0, 0, 0, 0, 0xffffffff00000000, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);
        let sc_data = syscall(libc::SYS_sendto, [0, 0, 0, 0, 0x00000000ffffffff, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::KillProcess, "Failed, ret = 0x{:?}", ret);

        let sc_data = syscall(libc::SYS_sendto, [0, 0, 0, 0, 0, 0]);
        let ret = run_seccomp(&prog, sc_data).unwrap();
        assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);
    }


    // #[test_log::test]
    // fn fcntl_lock_ok() {
    //     let prog = promises_to_prog(vec![StdIO, CPath, FLock],
    //                                 ViolationAction::KillProcess).unwrap();
    //     let sc_data = syscall(libc::SYS_fcntl, [42, libc::F_GETLK as u64, 0, 0, 0, 0]);

    //     let ret = run_seccomp(prog, sc_data).unwrap();

    //     assert!(ret == SeccompReturn::Allow, "Failed, ret = 0x{:?}", ret);
    // }


}
