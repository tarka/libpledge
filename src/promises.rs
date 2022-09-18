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

lazy_static! {
    static ref promises: HashMap<Promise, Vec<libc::c_long>> = HashMap::from([
        (Promise::Default, vec!{ libc::SYS_exit, }),
        (Promise::StdIO, vec!{
            libc::SYS_rt_sigreturn,
            libc::SYS_restart_syscall,
            libc::SYS_exit_group,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_clock_getres,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_close_range,
            libc::SYS_close,
            libc::SYS_write,
            libc::SYS_writev,
            libc::SYS_pwrite64,
            libc::SYS_pwritev,
            libc::SYS_pwritev2,
            libc::SYS_read,
            libc::SYS_readv,
            libc::SYS_pread64,
            libc::SYS_preadv,
            libc::SYS_preadv2,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_fchdir,
            libc::SYS_fcntl,// | STDIO,
            libc::SYS_fstat,
            libc::SYS_fsync,
            libc::SYS_sysinfo,
            libc::SYS_fdatasync,
            libc::SYS_ftruncate,
            libc::SYS_getrandom,
            libc::SYS_getgroups,
            libc::SYS_getpgid,
            libc::SYS_getpgrp,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_getsid,
            libc::SYS_getppid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
            libc::SYS_getrlimit,
            libc::SYS_getresgid,
            libc::SYS_getresuid,
            libc::SYS_getitimer,
            libc::SYS_setitimer,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
            libc::SYS_copy_file_range,
            libc::SYS_gettimeofday,
            libc::SYS_sendfile,
            libc::SYS_vmsplice,
            libc::SYS_splice,
            libc::SYS_lseek,
            libc::SYS_tee,
            libc::SYS_brk,
            libc::SYS_msync,
            libc::SYS_mmap,// | NOEXEC,
            libc::SYS_mremap,
            libc::SYS_munmap,
            libc::SYS_mincore,
            libc::SYS_madvise,
            libc::SYS_fadvise64,
            libc::SYS_mprotect,// | NOEXEC,
            libc::SYS_arch_prctl,
            libc::SYS_migrate_pages,
            libc::SYS_sync_file_range,
            libc::SYS_set_tid_address,
            libc::SYS_membarrier,
            libc::SYS_nanosleep,
            libc::SYS_pipe,
            libc::SYS_pipe2,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_select,
            libc::SYS_pselect6,
            libc::SYS_epoll_create,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_recvfrom,
            libc::SYS_sendto,// | ADDRLESS,
            libc::SYS_ioctl,// | RESTRICT,
            libc::SYS_alarm,
            libc::SYS_pause,
            libc::SYS_shutdown,
            libc::SYS_eventfd,
            libc::SYS_eventfd2,
            libc::SYS_signalfd,
            libc::SYS_signalfd4,
            libc::SYS_rt_sigaction,
            libc::SYS_sigaltstack,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigsuspend,
            libc::SYS_rt_sigpending,
            libc::SYS_kill,// | SELF,
            libc::SYS_tkill,// | SELF,
            libc::SYS_socketpair,
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_umask,
            libc::SYS_wait4,
            libc::SYS_uname,
            libc::SYS_prctl,// | STDIO,
            libc::SYS_clone,// | THREAD,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_prlimit64,// | STDIO,
        })

    ]);
}
