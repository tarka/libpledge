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

mod seccomp;

use std::{fs::File, io::{BufReader, BufRead}, time::{SystemTime, UNIX_EPOCH}};

use libc;
use nix::{unistd::{fork, ForkResult}, sys::{wait::{waitpid, WaitStatus}, signal::Signal}};
use oath::{pledge, Promise::*, ViolationAction};



#[test]
fn stdio_personality_errno() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == 0);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::Errno(999)).unwrap();

        let ret = unsafe { libc::personality(0xffffffff) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap();

        if ret != -1 || errno != 999 {
            unsafe { libc::exit(-1) };
        }
    }
}


#[test]
fn stdio_personality_killed() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Signaled(p2, sig, _) => {
                assert!(p2 == pid);
                assert!(sig == Signal::SIGSYS);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::KillProcess).unwrap();

        let _ret = unsafe { libc::personality(0xffffffff) };
    }
}


#[test]
fn empty_exit_ok() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == 99);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::KillProcess).unwrap();
        unsafe {
            // glibc calls exit_group, which is blocked at this point.
            libc::syscall(libc::SYS_exit, 99)
        };
    }
}


#[test]
fn stdio_time_ok() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == 99);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::KillProcess).unwrap();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        println!("Timestamp is {}", ts);
        unsafe { libc::exit(99) };
    }
}


#[test]
fn stdio_exit_ok() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == 99);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::KillProcess).unwrap();
        unsafe { libc::exit(99) };
    }
}


#[test]
fn stdio_open_not_passwd() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Signaled(p2, sig, _) => {
                assert!(p2 == pid);
                assert!(sig == Signal::SIGSYS);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO ], ViolationAction::KillProcess).unwrap();
        let _fd = File::open("/etc/passwd");
        unsafe { libc::exit(99) };
    }
}

#[test]
fn rpath_open_passwd() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == 99);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO, RPath ], ViolationAction::KillProcess).unwrap();
        let fd = File::open("/etc/passwd").unwrap();
        let lines = BufReader::new(fd).lines();
        assert!(lines.count() > 0);
        unsafe { libc::exit(99) };
    }
}


#[test]
fn rpath_no_write() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Signaled(p2, sig, _) => {
                assert!(p2 == pid);
                assert!(sig == Signal::SIGSYS);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        pledge(vec![ StdIO, RPath ], ViolationAction::KillProcess).unwrap();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        let _fd = File::create(format!("target/{}.tmp", ts));
        unsafe { libc::exit(99) };
    }
}
