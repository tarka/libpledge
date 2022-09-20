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

use crate::seccomp::CustomFragFn;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Promise {
    Default,
    StdIO,
    RPath,
}

pub enum Filtered {
    Whitelist(libc::c_long),
    Fcntl_Stdio,
    Mmap_Noexec,
    Mprotect_Noexec,
    Sendto_Addrless,
    Ioctl_Restrict,
    Kill_Self,
    Tkill_Self,
    Prctl_Stdio,
    Clone_Thread,
    Prlimit64_Stdio,
}

lazy_static! {
    pub static ref PROMISES: HashMap<Promise, Vec<Filtered>> = HashMap::from([
        (Promise::Default, vec!{
            Filtered::Whitelist(libc::SYS_exit),
        }),
        (Promise::StdIO, vec!{
            Filtered::Whitelist(libc::SYS_rt_sigreturn),
            Filtered::Whitelist(libc::SYS_restart_syscall),
            Filtered::Whitelist(libc::SYS_exit_group),
            Filtered::Whitelist(libc::SYS_sched_yield),
            Filtered::Whitelist(libc::SYS_sched_getaffinity),
            Filtered::Whitelist(libc::SYS_clock_getres),
            Filtered::Whitelist(libc::SYS_clock_gettime),
            Filtered::Whitelist(libc::SYS_clock_nanosleep),
            Filtered::Whitelist(libc::SYS_close_range),
            Filtered::Whitelist(libc::SYS_close),
            Filtered::Whitelist(libc::SYS_write),
            Filtered::Whitelist(libc::SYS_writev),
            Filtered::Whitelist(libc::SYS_pwrite64),
            Filtered::Whitelist(libc::SYS_pwritev),
            Filtered::Whitelist(libc::SYS_pwritev2),
            Filtered::Whitelist(libc::SYS_read),
            Filtered::Whitelist(libc::SYS_readv),
            Filtered::Whitelist(libc::SYS_pread64),
            Filtered::Whitelist(libc::SYS_preadv),
            Filtered::Whitelist(libc::SYS_preadv2),
            Filtered::Whitelist(libc::SYS_dup),
            Filtered::Whitelist(libc::SYS_dup2),
            Filtered::Whitelist(libc::SYS_dup3),
            Filtered::Whitelist(libc::SYS_fchdir),
            Filtered::Whitelist(libc::SYS_fcntl),// | STDIO,
            Filtered::Whitelist(libc::SYS_fstat),
            Filtered::Whitelist(libc::SYS_fsync),
            Filtered::Whitelist(libc::SYS_sysinfo),
            Filtered::Whitelist(libc::SYS_fdatasync),
            Filtered::Whitelist(libc::SYS_ftruncate),
            Filtered::Whitelist(libc::SYS_getrandom),
            Filtered::Whitelist(libc::SYS_getgroups),
            Filtered::Whitelist(libc::SYS_getpgid),
            Filtered::Whitelist(libc::SYS_getpgrp),
            Filtered::Whitelist(libc::SYS_getpid),
            Filtered::Whitelist(libc::SYS_gettid),
            Filtered::Whitelist(libc::SYS_getuid),
            Filtered::Whitelist(libc::SYS_getgid),
            Filtered::Whitelist(libc::SYS_getsid),
            Filtered::Whitelist(libc::SYS_getppid),
            Filtered::Whitelist(libc::SYS_geteuid),
            Filtered::Whitelist(libc::SYS_getegid),
            Filtered::Whitelist(libc::SYS_getrlimit),
            Filtered::Whitelist(libc::SYS_getresgid),
            Filtered::Whitelist(libc::SYS_getresuid),
            Filtered::Whitelist(libc::SYS_getitimer),
            Filtered::Whitelist(libc::SYS_setitimer),
            Filtered::Whitelist(libc::SYS_timerfd_create),
            Filtered::Whitelist(libc::SYS_timerfd_settime),
            Filtered::Whitelist(libc::SYS_timerfd_gettime),
            Filtered::Whitelist(libc::SYS_copy_file_range),
            Filtered::Whitelist(libc::SYS_gettimeofday),
            Filtered::Whitelist(libc::SYS_sendfile),
            Filtered::Whitelist(libc::SYS_vmsplice),
            Filtered::Whitelist(libc::SYS_splice),
            Filtered::Whitelist(libc::SYS_lseek),
            Filtered::Whitelist(libc::SYS_tee),
            Filtered::Whitelist(libc::SYS_brk),
            Filtered::Whitelist(libc::SYS_msync),
            Filtered::Whitelist(libc::SYS_mmap),// | NOEXEC,
            Filtered::Whitelist(libc::SYS_mremap),
            Filtered::Whitelist(libc::SYS_munmap),
            Filtered::Whitelist(libc::SYS_mincore),
            Filtered::Whitelist(libc::SYS_madvise),
            Filtered::Whitelist(libc::SYS_fadvise64),
            Filtered::Whitelist(libc::SYS_mprotect),// | NOEXEC,
            Filtered::Whitelist(libc::SYS_arch_prctl),
            Filtered::Whitelist(libc::SYS_migrate_pages),
            Filtered::Whitelist(libc::SYS_sync_file_range),
            Filtered::Whitelist(libc::SYS_set_tid_address),
            Filtered::Whitelist(libc::SYS_membarrier),
            Filtered::Whitelist(libc::SYS_nanosleep),
            Filtered::Whitelist(libc::SYS_pipe),
            Filtered::Whitelist(libc::SYS_pipe2),
            Filtered::Whitelist(libc::SYS_poll),
            Filtered::Whitelist(libc::SYS_ppoll),
            Filtered::Whitelist(libc::SYS_select),
            Filtered::Whitelist(libc::SYS_pselect6),
            Filtered::Whitelist(libc::SYS_epoll_create),
            Filtered::Whitelist(libc::SYS_epoll_create1),
            Filtered::Whitelist(libc::SYS_epoll_ctl),
            Filtered::Whitelist(libc::SYS_epoll_wait),
            Filtered::Whitelist(libc::SYS_epoll_pwait),
            Filtered::Whitelist(libc::SYS_epoll_pwait2),
            Filtered::Whitelist(libc::SYS_recvfrom),
            Filtered::Whitelist(libc::SYS_sendto),// | ADDRLESS,
            Filtered::Whitelist(libc::SYS_ioctl),// | RESTRICT,
            Filtered::Whitelist(libc::SYS_alarm),
            Filtered::Whitelist(libc::SYS_pause),
            Filtered::Whitelist(libc::SYS_shutdown),
            Filtered::Whitelist(libc::SYS_eventfd),
            Filtered::Whitelist(libc::SYS_eventfd2),
            Filtered::Whitelist(libc::SYS_signalfd),
            Filtered::Whitelist(libc::SYS_signalfd4),
            Filtered::Whitelist(libc::SYS_rt_sigaction),
            Filtered::Whitelist(libc::SYS_sigaltstack),
            Filtered::Whitelist(libc::SYS_rt_sigprocmask),
            Filtered::Whitelist(libc::SYS_rt_sigsuspend),
            Filtered::Whitelist(libc::SYS_rt_sigpending),
            Filtered::Whitelist(libc::SYS_kill),// | SELF,
            Filtered::Whitelist(libc::SYS_tkill),// | SELF,
            Filtered::Whitelist(libc::SYS_socketpair),
            Filtered::Whitelist(libc::SYS_getrusage),
            Filtered::Whitelist(libc::SYS_times),
            Filtered::Whitelist(libc::SYS_umask),
            Filtered::Whitelist(libc::SYS_wait4),
            Filtered::Whitelist(libc::SYS_uname),
            Filtered::Whitelist(libc::SYS_prctl),// | STDIO,
            Filtered::Whitelist(libc::SYS_clone),// | THREAD,
            Filtered::Whitelist(libc::SYS_futex),
            Filtered::Whitelist(libc::SYS_set_robust_list),
            Filtered::Whitelist(libc::SYS_get_robust_list),
            Filtered::Whitelist(libc::SYS_prlimit64),// | STDIO,
        }),

    ]);
}
