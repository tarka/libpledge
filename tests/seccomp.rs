/*
 * Copyright © 2022, Steve Smith <tarkasteve@gmail.com>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 3 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
    assert!(ret == -1);

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap();

    assert!(errno == 1000);

    Ok(())
}
