
// FIXME: Temp, remove once used properly
#![allow(warnings, unused)]


use libc::sock_filter;

use crate::errors::{Error, Result};

#[repr(u32)]
pub enum Size {
    U32 = libc::BPF_W,
    U16 = libc::BPF_H,
    U8 = libc::BPF_B,
}

pub enum Src {
    /// Contents of K instruction parameter
    Const(),
    /// Contents of index
    Idx(),
    /// Contents of accumulator
    Acc(),
}

#[repr(u32)]
pub enum Mode {
    IMM(u32),
    ABS(u32, Size),
    IND(u32, Size),
    MEM(u32),
    LEN,
}

pub enum AluOp {
    ADD(Src),
    SUB(Src),
    MUL(Src),
    DIV(Src),
    OR(Src),
    AND(Src),
    LSH(Src),
    RSH(Src),
    MOD(Src),
    XOR(Src),
}

pub struct CmpJmp {
    cmp: u32,
    jtrue: u8,
    jfalse: u8,
}

pub enum JmpOp {
    JA(u32),
    JEQ(CmpJmp),
    JGT(CmpJmp),
    JGE(CmpJmp),
    JSET(CmpJmp),
}

pub enum Instr {
    LD(Mode),
    LDX(Mode),
    ST(u32),
    STX(u32),
    ALU(AluOp),
    JMP(JmpOp),
    RET,
}
