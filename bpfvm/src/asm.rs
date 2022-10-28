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
    Jump(JmpOp, u32, Option<&'a str>, Option<&'a str>),
}
use Operation::*;

type Program<'a> = [Operation<'a>];


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

fn jmp_calc(labels: &HashMap<&str, usize>, label: &Option<&str>, curr: usize) -> Result<usize> {

    let jmp_off = match label {
        Some(l) => {
            let off = labels.get(l)
                .ok_or(Error::UnknownLabelReference(l.to_string()))?;
            *off - curr - 1
        },
        None => 0,
    };
    Ok(jmp_off)
}

fn to_sock_filter(linenum: usize, op: &Operation, labels: &HashMap<&str, usize>) -> Result<sock_filter> {
    let sf = match op {
        JumpTo(l) => {
            let targetline = jmp_calc(labels, &Some(l), linenum)?;
            bpf_jmp(JmpOp::JA, targetline as u32, 0, 0)
        },
        Jump(op, cmp, ltrue, lfalse) => {
            let lt = jmp_calc(labels, ltrue, linenum)?;
            let lf = jmp_calc(labels, lfalse, linenum)?;
            bpf_jmp(*op, *cmp, lt as u8, lf as u8)
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
        .enumerate()
        .map(|(linenum, op)| to_sock_filter(linenum, op, &labels))
        .collect();

    opcodes
}


#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use test_log;
    use crate::vm::{any_to_data, BpfVM};

    #[test_log::test]
    fn test_simple_jump() {
        let asm = vec![
            JumpTo("FAIL"),
            Label("OK"), Return(Src::Const, 0),
            Label("FAIL"), Return(Src::Const, 99),
        ];
        let prog = compile(&asm).unwrap();

        let mut vm = BpfVM::new(&prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_ld_gt_ret() {
        let asm = vec![
            Load(Mode::IMM, 99),
            Jump(JmpOp::JGT, 98, Some("ret_acc"), Some("ret999")),
            // Should skip this one
            Label("ret999"),
            Load(Mode::IMM, 999),
            Label("ret_acc"),
            Return(Src::Acc, 0),
        ];
        let prog = compile(&asm).unwrap();

        let mut vm = BpfVM::new(&prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }


    // Complex case from Cosmopolitan pledge() impl:
    //
    // The family parameter of socket() must be one of:
    //
    //   - AF_INET  (0x02)
    //   - AF_INET6 (0x0a)
    //
    // The type parameter of socket() will ignore:
    //
    //   - SOCK_CLOEXEC  (0x80000)
    //   - SOCK_NONBLOCK (0x00800)
    //
    // The type parameter of socket() must be one of:
    //
    //   - SOCK_STREAM (0x01)
    //   - SOCK_DGRAM  (0x02)
    //
    // The protocol parameter of socket() must be one of:
    //
    //   - 0
    //   - IPPROTO_ICMP (0x01)
    //   - IPPROTO_TCP  (0x06)
    //   - IPPROTO_UDP  (0x11)
    //
    #[ignore]
    #[test_log::test]
    fn test_cosmo_socket_filter() {
        use JmpOp::*;
        use Mode::*;
        use Src::*;
        use crate::seccomp::FieldOffset::*;

        let asm = vec![
            Load(ABS, Syscall.offset()),
            Jump(JEQ, libc::SYS_socket as u32, None, Some("REJECT")),

            // The family parameter of socket() must be one of:
            //
            //   - AF_INET  (0x02)
            //   - AF_INET6 (0x0a)
            //
            Load(ABS, ArgLower(0).offset()),
            Jump(JEQ, libc::AF_INET as u32, Some("Type_Check"), None),
            Jump(JEQ, libc::AF_INET6 as u32, Some("Type_Check"), Some("REJECT")),

            // The type parameter of socket() will ignore:
            //
            //   - SOCK_CLOEXEC  (0x80000)
            //   - SOCK_NONBLOCK (0x00800)
            //
            // The type parameter of socket() must be one of:
            //
            //   - SOCK_STREAM (0x01)
            //   - SOCK_DGRAM  (0x02)
            //
            Label("Type_Check"),
            Load(ABS, ArgLower(1).offset()),
            Alu(AluOp::AND, Const, !0x80800),
            Jump(JEQ, libc::SOCK_STREAM as u32, Some("Proto_Check"), None),
            Jump(JEQ, libc::SOCK_DGRAM as u32, Some("Proto_Check"), Some("REJECT")),

            // The protocol parameter of socket() must be one of:
            //
            //   - 0
            //   - IPPROTO_ICMP (0x01)
            //   - IPPROTO_TCP  (0x06)
            //   - IPPROTO_UDP  (0x11)
            //
            Label("Proto_Check"),
            Load(ABS, ArgLower(1).offset()),
            Jump(JEQ, 0, Some("ALLOW"), None),
            Jump(JEQ, libc::IPPROTO_ICMP as u32, Some("ALLOW"), None),
            Jump(JEQ, libc::IPPROTO_TCP as u32, Some("ALLOW"), None),
            Jump(JEQ, libc::IPPROTO_UDP as u32, Some("ALLOW"), None),

            JumpTo("REJECT"),

            Label("ALLOW"),
            Return(Const, 0),

            Label("REJECT"),
            Return(Const, 99),
        ];
        let prog = compile(&asm).unwrap();
        let mut vm = BpfVM::new(&prog).unwrap();

        let sc_data = libc::seccomp_data {
            nr: libc::SYS_open as i32,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        };
        let data = any_to_data(&sc_data);
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);

        let sc_data = libc::seccomp_data {
            nr: libc::SYS_socket as i32,
            arch: 0,
            instruction_pointer: 0,
            args: [
                libc::AF_INET as u64,
                (libc::SOCK_STREAM | libc::SOCK_NONBLOCK) as u64,
                libc::IPPROTO_TCP as u64,
                0, 0, 0
            ],
        };
        let data = any_to_data(&sc_data);
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0);
    }

}
