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

use lazy_static::lazy_static;
use libc;
use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Promise {
    Default,
    StdIO,
    RPath,
    WPath,
    CPath,
    DPath,
    FLock,
    FAttr,
    Inet,
}
use Promise::*;

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum Filtered {
    Whitelist(libc::c_long),
    FcntlStdio,
    // MmapNoexec,
    // MprotectNoexec,
    // SendtoAddrless,
    // IoctlRestrict,
    // KillSelf,
    // TkillSelf,
    // PrctlStdio,
    // CloneThread,
    // Prlimit64Stdio,
    // OpenReadonly,
    OpenatReadonly,
    // OpenWriteonly,
    OpenatWriteonly,
    // ChmodNobits,
    // FchmodNobits,
    // FchmodatNobits,
    // OpenCreateonly,
    OpenatCreateonly,
    // CreatRestrict,
    // FcntlLock,
    // SocketInet,
    // IoctlInet,
    // GetsockoptRestrict,
    // SetsockoptRestrict,
}
use Filtered::*;

lazy_static! {
    pub(crate) static ref PROMISES: HashMap<Promise, Vec<Filtered>> = HashMap::from([
        (
            Default,
            vec! {
                Whitelist(libc::SYS_exit),
            }
        ),
        (
            StdIO,
            vec! {
                Whitelist(libc::SYS_rt_sigreturn),
                Whitelist(libc::SYS_restart_syscall),
                Whitelist(libc::SYS_exit_group),
                Whitelist(libc::SYS_sched_yield),
                Whitelist(libc::SYS_sched_getaffinity),
                Whitelist(libc::SYS_clock_getres),
                Whitelist(libc::SYS_clock_gettime),
                Whitelist(libc::SYS_clock_nanosleep),
                Whitelist(libc::SYS_close_range),
                Whitelist(libc::SYS_close),
                Whitelist(libc::SYS_write),
                Whitelist(libc::SYS_writev),
                Whitelist(libc::SYS_pwrite64),
                Whitelist(libc::SYS_pwritev),
                Whitelist(libc::SYS_pwritev2),
                Whitelist(libc::SYS_read),
                Whitelist(libc::SYS_readv),
                Whitelist(libc::SYS_pread64),
                Whitelist(libc::SYS_preadv),
                Whitelist(libc::SYS_preadv2),
                Whitelist(libc::SYS_dup),
                Whitelist(libc::SYS_dup2),
                Whitelist(libc::SYS_dup3),
                Whitelist(libc::SYS_fchdir),
                FcntlStdio,
                Whitelist(libc::SYS_fstat),
                Whitelist(libc::SYS_fsync),
                Whitelist(libc::SYS_sysinfo),
                Whitelist(libc::SYS_fdatasync),
                Whitelist(libc::SYS_ftruncate),
                Whitelist(libc::SYS_getrandom),
                Whitelist(libc::SYS_getgroups),
                Whitelist(libc::SYS_getpgid),
                Whitelist(libc::SYS_getpgrp),
                Whitelist(libc::SYS_getpid),
                Whitelist(libc::SYS_gettid),
                Whitelist(libc::SYS_getuid),
                Whitelist(libc::SYS_getgid),
                Whitelist(libc::SYS_getsid),
                Whitelist(libc::SYS_getppid),
                Whitelist(libc::SYS_geteuid),
                Whitelist(libc::SYS_getegid),
                Whitelist(libc::SYS_getrlimit),
                Whitelist(libc::SYS_getresgid),
                Whitelist(libc::SYS_getresuid),
                Whitelist(libc::SYS_getitimer),
                Whitelist(libc::SYS_setitimer),
                Whitelist(libc::SYS_timerfd_create),
                Whitelist(libc::SYS_timerfd_settime),
                Whitelist(libc::SYS_timerfd_gettime),
                Whitelist(libc::SYS_copy_file_range),
                Whitelist(libc::SYS_gettimeofday),
                Whitelist(libc::SYS_sendfile),
                Whitelist(libc::SYS_vmsplice),
                Whitelist(libc::SYS_splice),
                Whitelist(libc::SYS_lseek),
                Whitelist(libc::SYS_tee),
                Whitelist(libc::SYS_brk),
                Whitelist(libc::SYS_msync),
//                MmapNoexec,
                Whitelist(libc::SYS_mremap),
                Whitelist(libc::SYS_munmap),
                Whitelist(libc::SYS_mincore),
                Whitelist(libc::SYS_madvise),
                Whitelist(libc::SYS_fadvise64),
//                MprotectNoexec,
                Whitelist(libc::SYS_arch_prctl),
                Whitelist(libc::SYS_migrate_pages),
                Whitelist(libc::SYS_sync_file_range),
                Whitelist(libc::SYS_set_tid_address),
                Whitelist(libc::SYS_membarrier),
                Whitelist(libc::SYS_nanosleep),
                Whitelist(libc::SYS_pipe),
                Whitelist(libc::SYS_pipe2),
                Whitelist(libc::SYS_poll),
                Whitelist(libc::SYS_ppoll),
                Whitelist(libc::SYS_select),
                Whitelist(libc::SYS_pselect6),
                Whitelist(libc::SYS_epoll_create),
                Whitelist(libc::SYS_epoll_create1),
                Whitelist(libc::SYS_epoll_ctl),
                Whitelist(libc::SYS_epoll_wait),
                Whitelist(libc::SYS_epoll_pwait),
                Whitelist(libc::SYS_epoll_pwait2),
                Whitelist(libc::SYS_recvfrom),
//                SendtoAddrless,
//                IoctlRestrict,
                Whitelist(libc::SYS_alarm),
                Whitelist(libc::SYS_pause),
                Whitelist(libc::SYS_shutdown),
                Whitelist(libc::SYS_eventfd),
                Whitelist(libc::SYS_eventfd2),
                Whitelist(libc::SYS_signalfd),
                Whitelist(libc::SYS_signalfd4),
                Whitelist(libc::SYS_rt_sigaction),
                Whitelist(libc::SYS_sigaltstack),
                Whitelist(libc::SYS_rt_sigprocmask),
                Whitelist(libc::SYS_rt_sigsuspend),
                Whitelist(libc::SYS_rt_sigpending),
//                KillSelf,
//                TkillSelf,
                Whitelist(libc::SYS_socketpair),
                Whitelist(libc::SYS_getrusage),
                Whitelist(libc::SYS_times),
                Whitelist(libc::SYS_umask),
                Whitelist(libc::SYS_wait4),
                Whitelist(libc::SYS_uname),
//                PrctlStdio,
//                CloneThread,
                Whitelist(libc::SYS_futex),
                Whitelist(libc::SYS_set_robust_list),
                Whitelist(libc::SYS_get_robust_list),
//                Prlimit64Stdio,
            }
        ),
        (
            RPath,
            vec! {
                Whitelist(libc::SYS_chdir),
                Whitelist(libc::SYS_getcwd),
//                OpenReadonly,
                OpenatReadonly,
                Whitelist(libc::SYS_stat),
                Whitelist(libc::SYS_lstat),
                Whitelist(libc::SYS_fstat),
                Whitelist(libc::SYS_newfstatat),
                Whitelist(libc::SYS_access),
                Whitelist(libc::SYS_faccessat),
                Whitelist(libc::SYS_faccessat2),
                Whitelist(libc::SYS_readlink),
                Whitelist(libc::SYS_readlinkat),
                Whitelist(libc::SYS_statfs),
                Whitelist(libc::SYS_fstatfs),
                Whitelist(libc::SYS_getdents),
            }
        ),
        (
            WPath,
            vec! {
                Whitelist(libc::SYS_getcwd),
//                OpenWriteonly,
                OpenatWriteonly,
                Whitelist(libc::SYS_stat),
                Whitelist(libc::SYS_fstat),
                Whitelist(libc::SYS_lstat),
                Whitelist(libc::SYS_newfstatat),
                Whitelist(libc::SYS_access),
                Whitelist(libc::SYS_truncate),
                Whitelist(libc::SYS_faccessat),
                Whitelist(libc::SYS_faccessat2),
                Whitelist(libc::SYS_readlinkat),
                // ChmodNobits,
                // FchmodNobits,
                // FchmodatNobits,
            }
        ),
        (
            CPath,
            vec! {
                // OpenCreateonly,
                OpenatCreateonly,
                // CreatRestrict,
                Whitelist(libc::SYS_rename),
                Whitelist(libc::SYS_renameat),
                Whitelist(libc::SYS_renameat2),
                Whitelist(libc::SYS_link),
                Whitelist(libc::SYS_linkat),
                Whitelist(libc::SYS_symlink),
                Whitelist(libc::SYS_symlinkat),
                Whitelist(libc::SYS_rmdir),
                Whitelist(libc::SYS_unlink),
                Whitelist(libc::SYS_unlinkat),
                Whitelist(libc::SYS_mkdir),
                Whitelist(libc::SYS_mkdirat),
            }
        ),
        (
            DPath,
            vec! {
                Whitelist(libc::SYS_mknod),
                Whitelist(libc::SYS_mknodat),
            }
        ),
        (
            FLock,
            vec! {
                Whitelist(libc::SYS_flock),
//                FcntlLock,
            }
        ),
        (
            FAttr,
            vec! {
                // ChmodNobits,
                // FchmodNobits,
                // FchmodatNobits,
                Whitelist(libc::SYS_utime),
                Whitelist(libc::SYS_utimes),
                Whitelist(libc::SYS_futimesat),
                Whitelist(libc::SYS_utimensat),
            }
        ),
        (
            Inet,
            vec! {
//                SocketInet,
                Whitelist(libc::SYS_listen),
                Whitelist(libc::SYS_bind),
                Whitelist(libc::SYS_sendto),
                Whitelist(libc::SYS_connect),
                Whitelist(libc::SYS_accept),
                Whitelist(libc::SYS_accept4),
                // IoctlInet,
                // GetsockoptRestrict,
                // SetsockoptRestrict,
                Whitelist(libc::SYS_getpeername),
                Whitelist(libc::SYS_getsockname),
            }
        ),
    ]);
}
