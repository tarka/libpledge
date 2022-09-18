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
use std::env::consts::ARCH;

#[test]
fn simple() -> Result<(), BackendError> {
    // Try then block an innocuous syscall.
    let ret = unsafe { libc::personality(0xffffffff) };
    assert!(ret != -1);

    let filter = Filter::new(
        vec![(
            libc::SYS_personality,
            vec![
                Rule::new(vec![
                    Cond::new(
                        0,
                        ArgLen::Dword,
                        CmpOp::Eq,
                        0xffffffff,
                    )?
                ])?
            ],
        )].into_iter().collect(),
        Action::Allow,
        Action::Errno(1000),
        ARCH.try_into()?,
    )?;

    let bpf_prog: BpfProgram = filter.try_into()?;
    apply_filter(&bpf_prog).unwrap();

    let ret = unsafe { libc::personality(0xffffffff) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap();

    assert!(ret == -1);
    assert!(errno == 1000);

    Ok(())
}
