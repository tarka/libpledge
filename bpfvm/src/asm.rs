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

use std::collections::HashMap;

use libc::sock_filter;
use crate::bpf::*;
use crate::errors::{Error, Result};


#[derive(Eq, PartialEq, Debug)]
pub enum Operation<'a> {
    Label(&'a str),
    Load(Mode, u32),
    LoadIdx(Mode, u32),
    Store(Mode, u32),
    StoreIdx(Mode, u32),
    Alu(AluOp, Src, u32),
    Return(Src, u32),
    JumpTo(&'a str), // Special case JMP_JA
    Jump(JmpOp, u32, &'a str, &'a str),
}
use Operation::*;

type Program<'a> = Vec<Operation<'a>>;



fn map_labels<'a>(prog: &'a Program) -> Result<HashMap<&'a str, usize>> {
    // FIXME: If I get bored, convert this to an iter workflow.
    let mut line = 0;
    let mut labels: HashMap<&'a str, usize> = HashMap::new();
    for op in prog {
        match op {
            Label(l) => {
                labels.insert(l, line);
            },
            _ => {
                line += 1;
            }
        }
    }

    Ok(labels)
}

fn get_label(labels: &HashMap<&str, usize>, label: &str) -> Result<usize> {
    let linenum = labels.get(label)
        .ok_or(Error::UnknownLabelReference(label.to_string()))?;
    Ok(*linenum)
}

fn to_sock_filter(op: &Operation, labels: &HashMap<&str, usize>) -> Result<sock_filter> {
    let sf = match op {
        JumpTo(l) => {
            let linenum = get_label(labels, l)?;
            bpf_jmp(JmpOp::JA, (linenum - 1) as u32, 0, 0)
        },
        Jump(op, cmp, ltrue, lfalse) => {
            let lt = get_label(labels, ltrue)?;
            let lf = get_label(labels, lfalse)?;
            bpf_jmp(*op, *cmp, (lt - 1) as u8, (lf - 1) as u8)
        },
        Load(mode, val) => bpf_ld(*mode, *val),
        LoadIdx(mode, val) => bpf_ldx(*mode, *val),
        Store(mode, val) => bpf_st(*mode, *val),
        StoreIdx(mode, val) => bpf_stx(*mode, *val),
        Alu(op, src, val) => bpf_alu(*op, *src, *val),
        Return(src, val) => bpf_ret(*src, *val),
        Label(l) => return Err(Error::UnknownLabelReference(l.to_string())),
    };

    Ok(sf)
}


pub fn compile(prog: &Program) -> Result<Vec<sock_filter>> {
    let labels = map_labels(prog)?;

    // TODO: We should probably do forward-only jump checks,
    // etc. here.

    let opcodes = prog.into_iter()
        .filter(|op| !matches!(op, Label(_)))
        .map(|op| to_sock_filter(op, &labels))
        .collect();
    opcodes

}



#[cfg(test)]
mod tests {
    use test_log;
    use super::*;
    use crate::BpfVM;

    #[test_log::test]
    fn test_simple_jump() {
        let asm = vec![
            JumpTo("FAIL"),
            Label("OK"), Return(Src::Const, 0),
            Label("FAIL"), Return(Src::Const, 99),
        ];
        let prog = compile(&asm).unwrap();

        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

}
