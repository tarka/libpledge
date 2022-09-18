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
}

enum Filtered {
    Simple(libc::c_long),
    Custom(fn()),
}

lazy_static! {
    static ref promises: HashMap<Promise, Vec<Filtered>> = HashMap::from([
        (Promise::Default, vec!{
            Filtered::Simple(libc::SYS_exit),
        }),
        (Promise::StdIO, vec!{
            Filtered::Simple(libc::SYS_rt_sigreturn),
            Filtered::Simple(libc::SYS_restart_syscall),
            Filtered::Simple(libc::SYS_exit_group),
            Filtered::Simple(libc::SYS_sched_yield),
            Filtered::Simple(libc::SYS_sched_getaffinity),
            Filtered::Simple(libc::SYS_clock_getres),
            Filtered::Simple(libc::SYS_clock_gettime),
            Filtered::Simple(libc::SYS_clock_nanosleep),
            Filtered::Simple(libc::SYS_close_range),
            Filtered::Simple(libc::SYS_close),
            Filtered::Simple(libc::SYS_write),
            Filtered::Simple(libc::SYS_writev),
            Filtered::Simple(libc::SYS_pwrite64),
            Filtered::Simple(libc::SYS_pwritev),
            Filtered::Simple(libc::SYS_pwritev2),
            Filtered::Simple(libc::SYS_read),
            Filtered::Simple(libc::SYS_readv),
            Filtered::Simple(libc::SYS_pread64),
            Filtered::Simple(libc::SYS_preadv),
            Filtered::Simple(libc::SYS_preadv2),
            Filtered::Simple(libc::SYS_dup),
            Filtered::Simple(libc::SYS_dup2),
            Filtered::Simple(libc::SYS_dup3),
            Filtered::Simple(libc::SYS_fchdir),
            Filtered::Simple(libc::SYS_fcntl),// | STDIO,
            Filtered::Simple(libc::SYS_fstat),
            Filtered::Simple(libc::SYS_fsync),
            Filtered::Simple(libc::SYS_sysinfo),
            Filtered::Simple(libc::SYS_fdatasync),
            Filtered::Simple(libc::SYS_ftruncate),
            Filtered::Simple(libc::SYS_getrandom),
            Filtered::Simple(libc::SYS_getgroups),
            Filtered::Simple(libc::SYS_getpgid),
            Filtered::Simple(libc::SYS_getpgrp),
            Filtered::Simple(libc::SYS_getpid),
            Filtered::Simple(libc::SYS_gettid),
            Filtered::Simple(libc::SYS_getuid),
            Filtered::Simple(libc::SYS_getgid),
            Filtered::Simple(libc::SYS_getsid),
            Filtered::Simple(libc::SYS_getppid),
            Filtered::Simple(libc::SYS_geteuid),
            Filtered::Simple(libc::SYS_getegid),
            Filtered::Simple(libc::SYS_getrlimit),
            Filtered::Simple(libc::SYS_getresgid),
            Filtered::Simple(libc::SYS_getresuid),
            Filtered::Simple(libc::SYS_getitimer),
            Filtered::Simple(libc::SYS_setitimer),
            Filtered::Simple(libc::SYS_timerfd_create),
            Filtered::Simple(libc::SYS_timerfd_settime),
            Filtered::Simple(libc::SYS_timerfd_gettime),
            Filtered::Simple(libc::SYS_copy_file_range),
            Filtered::Simple(libc::SYS_gettimeofday),
            Filtered::Simple(libc::SYS_sendfile),
            Filtered::Simple(libc::SYS_vmsplice),
            Filtered::Simple(libc::SYS_splice),
            Filtered::Simple(libc::SYS_lseek),
            Filtered::Simple(libc::SYS_tee),
            Filtered::Simple(libc::SYS_brk),
            Filtered::Simple(libc::SYS_msync),
            Filtered::Simple(libc::SYS_mmap),// | NOEXEC,
            Filtered::Simple(libc::SYS_mremap),
            Filtered::Simple(libc::SYS_munmap),
            Filtered::Simple(libc::SYS_mincore),
            Filtered::Simple(libc::SYS_madvise),
            Filtered::Simple(libc::SYS_fadvise64),
            Filtered::Simple(libc::SYS_mprotect),// | NOEXEC,
            Filtered::Simple(libc::SYS_arch_prctl),
            Filtered::Simple(libc::SYS_migrate_pages),
            Filtered::Simple(libc::SYS_sync_file_range),
            Filtered::Simple(libc::SYS_set_tid_address),
            Filtered::Simple(libc::SYS_membarrier),
            Filtered::Simple(libc::SYS_nanosleep),
            Filtered::Simple(libc::SYS_pipe),
            Filtered::Simple(libc::SYS_pipe2),
            Filtered::Simple(libc::SYS_poll),
            Filtered::Simple(libc::SYS_ppoll),
            Filtered::Simple(libc::SYS_select),
            Filtered::Simple(libc::SYS_pselect6),
            Filtered::Simple(libc::SYS_epoll_create),
            Filtered::Simple(libc::SYS_epoll_create1),
            Filtered::Simple(libc::SYS_epoll_ctl),
            Filtered::Simple(libc::SYS_epoll_wait),
            Filtered::Simple(libc::SYS_epoll_pwait),
            Filtered::Simple(libc::SYS_epoll_pwait2),
            Filtered::Simple(libc::SYS_recvfrom),
            Filtered::Simple(libc::SYS_sendto),// | ADDRLESS,
            Filtered::Simple(libc::SYS_ioctl),// | RESTRICT,
            Filtered::Simple(libc::SYS_alarm),
            Filtered::Simple(libc::SYS_pause),
            Filtered::Simple(libc::SYS_shutdown),
            Filtered::Simple(libc::SYS_eventfd),
            Filtered::Simple(libc::SYS_eventfd2),
            Filtered::Simple(libc::SYS_signalfd),
            Filtered::Simple(libc::SYS_signalfd4),
            Filtered::Simple(libc::SYS_rt_sigaction),
            Filtered::Simple(libc::SYS_sigaltstack),
            Filtered::Simple(libc::SYS_rt_sigprocmask),
            Filtered::Simple(libc::SYS_rt_sigsuspend),
            Filtered::Simple(libc::SYS_rt_sigpending),
            Filtered::Simple(libc::SYS_kill),// | SELF,
            Filtered::Simple(libc::SYS_tkill),// | SELF,
            Filtered::Simple(libc::SYS_socketpair),
            Filtered::Simple(libc::SYS_getrusage),
            Filtered::Simple(libc::SYS_times),
            Filtered::Simple(libc::SYS_umask),
            Filtered::Simple(libc::SYS_wait4),
            Filtered::Simple(libc::SYS_uname),
            Filtered::Simple(libc::SYS_prctl),// | STDIO,
            Filtered::Simple(libc::SYS_clone),// | THREAD,
            Filtered::Simple(libc::SYS_futex),
            Filtered::Simple(libc::SYS_set_robust_list),
            Filtered::Simple(libc::SYS_get_robust_list),
            Filtered::Simple(libc::SYS_prlimit64),// | STDIO,
        }),

    ]);
}
