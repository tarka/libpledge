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
mod util;

use util::{fork_expect_code, fork_expect_sig};

use std::{
    fs::File,
    io::{BufRead, BufReader},
    time::{SystemTime, UNIX_EPOCH},
};

use libc;
use nix::sys::signal::Signal;
use oath::{pledge, pledge_override, Promise::*, ViolationAction};

#[test]
fn stdio_personality_errno() {
    fork_expect_code(0, || {
        pledge_override(vec![StdIO], ViolationAction::Errno(999)).unwrap();

        let ret = unsafe { libc::personality(0xffffffff) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap();

        if ret != -1 || errno != 999 {
            unsafe { libc::exit(-1) };
        }
    });
}

#[test]
fn stdio_personality_killed() {
    fork_expect_sig(Signal::SIGSYS, || {
        pledge(vec![StdIO]).unwrap();

        let _ret = unsafe { libc::personality(0xffffffff) };
    });
}

#[test]
fn empty_exit_ok() {
    fork_expect_code(99, || {
        pledge(vec![StdIO]).unwrap();
        unsafe {
            // glibc calls exit_group, which is blocked at this point.
            libc::syscall(libc::SYS_exit, 99)
        };
    });
}

#[test]
fn stdio_time_ok() {
    fork_expect_code(99, || {
        pledge(vec![StdIO]).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        println!("Timestamp is {}", ts);
        unsafe { libc::exit(99) };
    });
}

#[test]
fn stdio_exit_ok() {
    fork_expect_code(99, || {
        pledge(vec![StdIO]).unwrap();
        unsafe { libc::exit(99) };
    });
}

#[test]
fn stdio_open_not_passwd() {
    fork_expect_sig(Signal::SIGSYS, || {
        pledge(vec![StdIO]).unwrap();
        let _fd = File::open("/etc/passwd");
        unsafe { libc::exit(99) };
    });
}

#[test]
fn rpath_open_passwd() {
    fork_expect_code(99, || {
        pledge(vec![StdIO, RPath]).unwrap();
        let fd = File::open("/etc/passwd").unwrap();
        let lines = BufReader::new(fd).lines();
        assert!(lines.count() > 0);
        unsafe { libc::exit(99) };
    });
}

#[test]
fn rpath_no_write() {
    fork_expect_sig(Signal::SIGSYS, || {
        pledge(vec![StdIO, RPath]).unwrap();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let _fd = File::create(format!("target/{}.tmp", ts));
        unsafe { libc::exit(99) };
    });
}
