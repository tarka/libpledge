#![allow(warnings, unused)]

pub const BPF_A: u32 = 0x10; // Not defined in libc for some reason.


#[repr(u32)]
pub enum WordSize {
    U32 = libc::BPF_W,
    U16 = libc::BPF_H,
    U8 = libc::BPF_B,
}

#[repr(u32)]
pub enum Src {
    /// Contents of K instruction parameter
    Const = libc::BPF_K,
    /// Contents of index
    Idx = libc::BPF_X,
    /// Contents of accumulator
    Acc = BPF_A,
}

#[repr(u32)]
pub enum Mode {
    IMM = libc::BPF_IMM,
    ABS = libc::BPF_ABS,
    IND = libc::BPF_IND,
    MEM = libc::BPF_MEM,
    LEN = libc::BPF_LEN,
}

#[repr(u32)]
pub enum AluOp {
    ADD = libc::BPF_ADD,
    SUB = libc::BPF_SUB,
    MUL = libc::BPF_MUL,
    DIV = libc::BPF_DIV,
    OR = libc::BPF_OR,
    AND = libc::BPF_AND,
    LSH = libc::BPF_LSH,
    RSH = libc::BPF_RSH,
    MOD = libc::BPF_MOD,
    XOR = libc::BPF_XOR,
}

#[repr(u32)]
pub enum JmpOp {
    JA = libc::BPF_JA,
    JEQ = libc::BPF_JEQ,
    JGT = libc::BPF_JGT,
    JGE = libc::BPF_JGE,
    JSET = libc::BPF_JSET,
}

#[repr(u32)]
pub enum Instr {
    LD = libc::BPF_LD,
    LDX = libc::BPF_LDX,
    ST = libc::BPF_ST,
    STX = libc::BPF_STX,
    ALU = libc::BPF_ALU,
    JMP = libc::BPF_JMP,
    RET = libc::BPF_RET,
}

pub struct CmpJmp {
    cmp: u32,
    jtrue: u8,
    jfalse: u8,
}



#[cfg(test)]
mod tests {
    use libc::sock_filter;
    use test_log;
    use super::*;
    use crate::{any_to_data, BpfVM};

    const WORDS: u32 = 4;

    fn bpf_stmt(code: u32, val: u32) -> sock_filter {
        sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k: val,
        }
    }

    fn bpf_stmt_w(code: u32, val: u32) -> sock_filter {
        bpf_stmt(code | WordSize::U32 as u32, val)
    }

    fn bpf_ld(mode: Mode, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::LD as u32 | mode as u32, val)
    }

    fn bpf_ldx(mode: Mode, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::LDX as u32 | mode as u32, val)
    }

    fn bpf_st(mode: Mode, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::ST as u32 | mode as u32, val)
    }

    fn bpf_stx(mode: Mode, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::STX as u32 | mode as u32, val)
    }

    fn bpf_alu(op: AluOp, src: Src, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::ALU as u32 | op as u32 | src as u32, val)
    }

    fn bpf_ret(retval: Src, val: u32) -> sock_filter {
        bpf_stmt_w(Instr::RET as u32 | retval as u32, val)
    }

    fn bpf_jmp(op: JmpOp, k: u32, jt: u8, jf: u8) -> sock_filter {
        let code = Instr::JMP as u32 | op as u32;
        sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        }
    }

    #[test_log::test]
    fn test_ret() {
        let prog = vec![bpf_ret(Src::Const, 99)];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_load_and_ret() {
        let prog = vec![
            bpf_ld(Mode::IMM, 99),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_load_data() {
        let prog = vec![
            bpf_ld(Mode::ABS, 1*WORDS),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![0, 0xFFFFFFFF];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0xFFFFFFFF);
    }

    #[test_log::test]
    fn test_alu_mask() {
        let prog = vec![
            bpf_ld(Mode::ABS, 2*WORDS),
            bpf_stmt(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0xF0),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();

        let data = vec![0, 0, 0xFF, 0];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0xF0);

        let data = vec![0, 0, 0x80, 0];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0x80);
    }

    #[test_log::test]
    fn test_alu_mul() {
        let prog = vec![
            bpf_ld(Mode::ABS, 2*WORDS),
            bpf_alu(AluOp::MUL, Src::Const, 2),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();

        let data = vec![0, 0, 8, 0];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 16);
    }

    #[test_log::test]
    fn test_ld_ja_ret() {
        let prog = vec![
            bpf_ld(Mode::IMM, 99),
            bpf_jmp(JmpOp::JA, 1, 0, 0),
            // Should skip this one
            bpf_ld(Mode::IMM, 999),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_ld_gt_ret() {
        let prog = vec![
            bpf_ld(Mode::IMM, 99),
            bpf_jmp(JmpOp::JGT, 98, 1, 0),
            // Should skip this one
            bpf_ld(Mode::IMM, 999),
            bpf_ret(Src::Acc, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_seccomp_data_conv() {
        let sc_data = libc::seccomp_data {
            nr: 1,
            arch: 2,
            instruction_pointer: 3,
            args: [4, 5, 6, 7, 8, 9],
        };
        let data = any_to_data(&sc_data);

        let prog = vec![
            // NR
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 0*WORDS),
            bpf_jmp(JmpOp::JEQ, 1, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 100),
            // arch
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 1*WORDS),
            bpf_jmp(JmpOp::JEQ, 2, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 101),
            // inst_ptr
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 2*WORDS),
            bpf_jmp(JmpOp::JEQ, 3, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 102),
            // args[0] = [0, 4]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 3*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 103),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 4*WORDS),
            bpf_jmp(JmpOp::JEQ, 4, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 104),
            // args[0] = [0, 5]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 5*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 105),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 6*WORDS),
            bpf_jmp(JmpOp::JEQ, 5, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 106),
            // args[0] = [0, 6]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 7*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 107),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 8*WORDS),
            bpf_jmp(JmpOp::JEQ, 6, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 108),
            // args[0] = [0, 7]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 9*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 109),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 10*WORDS),
            bpf_jmp(JmpOp::JEQ, 7, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 110),
            // args[0] = [0, 8]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 11*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 111),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 12*WORDS),
            bpf_jmp(JmpOp::JEQ, 8, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 112),
            // args[0] = [0, 9]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 13*WORDS),
            bpf_jmp(JmpOp::JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 113),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 14*WORDS),
            bpf_jmp(JmpOp::JEQ, 9, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 114),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();

        let ret = vm.run(&data).unwrap();
        assert!(ret == 0, "Failed, ret = 0x{:x}", ret);
    }
}
