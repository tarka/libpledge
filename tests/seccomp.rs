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

use std::env::consts::ARCH;
use std::thread;

use libc;

use seccompiler::{SeccompAction, SeccompFilter, Error, BpfProgram, apply_filter};

#[test]
fn simple() -> Result<(), Error>{
    let filter = SeccompFilter::new(
        vec![
            (libc::SYS_personality, vec![]),
        ].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(1000),
        ARCH.try_into()?)?;

    let bpf_prog: BpfProgram = filter.try_into()?;

    let returned_errno = thread::spawn(move || {
        // Install the filter.
        apply_filter(&bpf_prog).unwrap();

        let ret = unsafe { libc::personality(0xffffffff) };
        assert!(ret == -1);

        // Return errno.
        std::io::Error::last_os_error().raw_os_error().unwrap()
    })
    .join()
    .unwrap();

    assert!(returned_errno == 1000);

    Ok(())
}
