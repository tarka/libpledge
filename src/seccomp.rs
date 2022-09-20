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
use std::{env::consts::ARCH, io};

use crate::{promises::{Promise, Filtered, PROMISES}, errors::{Result, Error}};

pub type WhitelistFrag = (libc::c_long, Vec<Rule>);
pub type CustomFragFn = fn() -> Result<WhitelistFrag>;


fn whitelist(syscal: &libc::c_long) -> Result<WhitelistFrag> {
    let wl = (
            libc::SYS_personality,
            vec![],
        );

    Ok(wl)
}


fn oath_to_bpf(filter: &Filtered) -> Result<WhitelistFrag> {
    match filter {
        Filtered::Whitelist(syscall) => whitelist(syscall),
        Filtered::Custom(func) => func()
    }
}


fn swear(promises: Vec<Promise>) -> Result<()> {

    // Convert all promises into filter specs.
    // FIXME: Should we dedup the list here?
    let filters = promises.into_iter()
        .map(|p| PROMISES.get(&p).ok_or(Error::UndefinedPromise(p)))
        .collect::<Result<Vec<&Vec<Filtered>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<&Filtered>>();

    let frags = filters.into_iter()
        .map(oath_to_bpf)
        .collect::<Result<Vec<WhitelistFrag>>>()?;

    Ok(())
}
