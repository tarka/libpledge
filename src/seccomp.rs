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

use libc;
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction as Action, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp as CmpOp, SeccompCondition as Cond, SeccompFilter, SeccompRule as Rule,
};
use std::{env::consts::ARCH, process};
use crate::{promises::{Promise, Filtered, PROMISES}, errors::{Result, Error}};


pub type WhitelistFrag = (libc::c_long, Vec<Rule>);


fn whitelist_syscall(syscall: libc::c_long) -> Result<WhitelistFrag> {
    let wl = (
        syscall,
        vec![],
    );

    Ok(wl)
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
    let wl = (
        libc::SYS_fcntl,
        vec![
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Le,
                    4,  // Arg == 0-4
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::F_DUPFD_CLOEXEC as u64
                )?
            ])?
        ]
    );
    Ok(wl)
}


// The flags parameter of mmap() must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
fn mmap_noexec() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_mmap,
        vec![
            Rule::new(vec![
                Cond::new(
                    3,
                    ArgLen::Dword,
                    CmpOp::MaskedEq(0x52000),
                    0
                )?
            ])?
        ]
    );
    Ok(wl)
}


// The prot parameter of mprotect() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
fn mprotect_noexec() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_mprotect,
        vec![
            Rule::new(vec![
                Cond::new(
                    2,
                    ArgLen::Dword,
                    CmpOp::Le,
                    2,  // Arg == 0-2
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The sockaddr parameter of sendto() must be
//
//   - NULL
//
fn sendto_addrless() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_sendto,
        vec![
            Rule::new(vec![
                Cond::new(
                    4,
                    ArgLen::Qword,
                    CmpOp::Eq,
                    0, // Null sockaddr pointer
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The second argument of ioctl() must be one of:
//
//   - FIONREAD (0x541b)
//   - FIONBIO  (0x5421)
//   - FIOCLEX  (0x5451)
//   - FIONCLEX (0x5450)
//
fn ioctl_restrict() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_ioctl,
        vec![
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::FIONREAD,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::FIONBIO,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::FIOCLEX,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    1,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::FIONCLEX,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The first argument of kill() must be
//
//   - getpid()
//
fn kill_self() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_kill,
        vec![
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    process::id() as u64,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The first argument of tkill() must be
//
//   - gettid()
//
fn tkill_self() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_tkill,
        vec![
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    unsafe { libc::gettid() } as u64,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The first parameter of prctl() can be any of
//
//   - PR_SET_NAME         (15)
//   - PR_GET_NAME         (16)
//   - PR_GET_SECCOMP      (21)
//   - PR_SET_SECCOMP      (22)
//   - PR_SET_NO_NEW_PRIVS (38)
//   - PR_CAPBSET_READ     (23)
//   - PR_CAPBSET_DROP     (24)
//
fn prctl_stdio() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_prctl,
        vec![
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_SET_NAME as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_GET_NAME as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_GET_SECCOMP as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_SET_SECCOMP as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_SET_NO_NEW_PRIVS as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_CAPBSET_READ as u64,
                )?
            ])?,
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::Eq,
                    libc::PR_CAPBSET_DROP as u64,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The first argument of sys_clone_linux() must have:
//
//   - CLONE_VM       (0x00000100)
//   - CLONE_FS       (0x00000200)
//   - CLONE_FILES    (0x00000400)
//   - CLONE_THREAD   (0x00010000)
//   - CLONE_SIGHAND  (0x00000800)
//
// The first argument of sys_clone_linux() must NOT have:
//
//   - CLONE_NEWNS    (0x00020000)
//   - CLONE_PTRACE   (0x00002000)
//   - CLONE_UNTRACED (0x00800000)
//
fn clone_thread() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_clone,
        vec![
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::MaskedEq(0x00010f00),
                    0x00010f00,
                )?,
                Cond::new(
                    0,
                    ArgLen::Dword,
                    CmpOp::MaskedEq(0x00822000),
                    0,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


// The new_limit parameter of prlimit() must be
//
//   - NULL (0)
//
fn prlimit64_stdio() -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_prlimit64,
        vec![
            Rule::new(vec![
                Cond::new(
                    0,
                    ArgLen::Qword,
                    CmpOp::Eq,
                    0,
                )?
            ])?,
        ]
    );
    Ok(wl)
}


fn oath_to_bpf(filter: &Filtered) -> Result<WhitelistFrag> {
    match filter {
        Filtered::Whitelist(syscall) => whitelist_syscall(*syscall),
        Filtered::FcntlStdio => fcntl_stdio(),
        Filtered::MmapNoexec => mmap_noexec(),
        Filtered::MprotectNoexec => mprotect_noexec(),
        Filtered::SendtoAddrless => sendto_addrless(),
        Filtered::IoctlRestrict => ioctl_restrict(),
        Filtered::KillSelf => kill_self(),
        Filtered::TkillSelf => tkill_self(),
        Filtered::PrctlStdio => prctl_stdio(),
        Filtered::CloneThread => clone_thread(),
        Filtered::Prlimit64Stdio => prlimit64_stdio(),
    }
}


pub fn swear(promises: Vec<Promise>) -> Result<()> {

    // Convert all promises into filter specs.
    // FIXME: Should we dedup the list here?
    let defaults = vec![ Promise::Default ];
    let filters = defaults.into_iter()
        .chain(promises.into_iter())
        .map(|p| PROMISES.get(&p).ok_or(Error::UndefinedPromise(p)))
        .collect::<Result<Vec<&Vec<Filtered>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<&Filtered>>();

    // Filters to seccompiler BPF IR
    let whitelist = filters.into_iter()
        .map(oath_to_bpf)
        .collect::<Result<Vec<WhitelistFrag>>>()?;

    let sf = SeccompFilter::new(
        whitelist.into_iter().collect(),
        Action::Errno(1000),
        Action::Allow,
        ARCH.try_into()?
    )?;

    let bpf_prog: BpfProgram = sf.try_into()?;
    apply_filter(&bpf_prog)?;

    Ok(())
}
