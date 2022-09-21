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


use libc::_exit;
use nix::{unistd::{fork, ForkResult}, sys::wait::{waitpid, WaitStatus}};
use oath::{swear, Promise::*, ViolationAction};

#[test]
fn stdio_personality_errno() {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) if p2 == pid => {
                assert!(code == 0);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        swear(vec![ StdIO ], ViolationAction::Errno(999)).unwrap();

        let ret = unsafe { libc::personality(0xffffffff) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap();

        if ret != -1 || errno != 999 {
            unsafe { _exit(-1) };
        }

    }
}
