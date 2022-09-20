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
    apply_filter, BackendError, BpfProgram, SeccompAction as Action, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp as CmpOp, SeccompCondition as Cond, SeccompFilter as Filter, SeccompRule as Rule,
};
use std::{env::consts::ARCH, io};
use crate::{promises::{Promise, Filtered, PROMISES}, errors::{Result, Error}};


pub type WhitelistFrag = (libc::c_long, Vec<Rule>);


fn whitelist_syscall(syscal: &libc::c_long) -> Result<WhitelistFrag> {
    let wl = (
        libc::SYS_personality,
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


fn ioctl_restrict() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn kill_self() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn tkill_self() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn prctl_stdio() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn clone_thread() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn prlimit64_stdio() -> Result<WhitelistFrag> {
    Ok((0, Vec::new()))  // FIXME
}


fn oath_to_bpf(filter: &Filtered) -> Result<WhitelistFrag> {
    match filter {
        Filtered::Whitelist(syscall) => whitelist_syscall(syscall),
        Filtered::Fcntl_Stdio => fcntl_stdio(),
        Filtered::Mmap_Noexec => mmap_noexec(),
        Filtered::Mprotect_Noexec => mprotect_noexec(),
        Filtered::Sendto_Addrless => sendto_addrless(),
        Filtered::Ioctl_Restrict => ioctl_restrict(),
        Filtered::Kill_Self => kill_self(),
        Filtered::Tkill_Self => tkill_self(),
        Filtered::Prctl_Stdio => prctl_stdio(),
        Filtered::Clone_Thread => clone_thread(),
        Filtered::Prlimit64_Stdio => prlimit64_stdio(),
    }
}


fn swear(promises: Vec<Promise>) -> Result<()> {

    // Convert all promises into filter specs.
    // FIXME: Should we dedup the list here?
    let filters = promises.into_iter()
        .map(|p| PROMISES.get(&p).ok_or(Error::UndefinedPromise(p)))
        .collect::<Result<Vec<&Vec<Filtered>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<&Filtered>>();

    let frags = filters.into_iter()
        .map(oath_to_bpf)
        .collect::<Result<Vec<WhitelistFrag>>>()?;

    Ok(())
}
