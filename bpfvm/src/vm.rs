use libc::sock_filter;
use log::{error, info};

use crate::errors::{Error, Result};

pub type FProg = Vec<sock_filter>;
const MEMSIZE: usize = libc::BPF_MEMWORDS as usize;
const BPF_A: u32 = 0x10; // Not defined in libc for some reason.

pub struct BpfVM {
    pub pc: usize,
    pub acc: u32,
    pub idx: u32,
    pub mem: [u32; MEMSIZE],
    pub prog: Vec<sock_filter>,
}

fn fetch_u32(data: &[u32], off: usize) -> Result<u32> {
    Ok(data[off])
}

fn fetch_u16(data: &[u32], off: usize) -> Result<u32> {
    // FIXME: Not supported by seccomp, implement later if needed
    Err(Error::UnsupportedDataOffset)
}

fn fetch_u8(data: &[u32], off: usize) -> Result<u32> {
    // FIXME: Not supported by seccomp, implement later if needed
    Err(Error::UnsupportedDataOffset)
}

fn fetch_data(data: &[u32], off: usize, size: u16) -> Result<u32> {
    match size as u32 {
        libc::BPF_W => fetch_u32(data, off),
        libc::BPF_H => fetch_u16(data, off),
        libc::BPF_B => fetch_u8(data, off),
        _ => return Err(Error::InvalidInstructionCode(size)),
    }
}

impl BpfVM {
    pub fn new(prog: FProg) -> Result<BpfVM> {
        if prog.len() > u16::MAX as usize {
            return Err(Error::ProgramTooLong(prog.len()));
        }

        Ok(BpfVM {
            pc: 0,
            acc: 0,
            idx: 0,
            mem: [0; MEMSIZE],
            prog: prog.clone(),
        })
    }

    pub fn reset(&mut self) -> Result<()> {
        self.pc = 0;
        self.acc = 0;
        self.idx = 0;
        self.mem = [0; MEMSIZE];
        Ok(())
    }

    fn fetch_src(&self, src: u16, curr: &sock_filter) -> Result<u32> {
        match src as u32 {
            libc::BPF_K => {
                info!("Src is K: {}", curr.k);
                return Ok(curr.k);
            }
            libc::BPF_X => {
                info!("Src is IDX: {}", self.idx);
                return Ok(self.idx);
            }
            BPF_A => {
                info!("Src is ACC: {}", self.acc);
                return Ok(self.acc);
            }
            _ => return Err(Error::InvalidInstructionCode(curr.code)),
        }
    }

    pub fn execute(&mut self, data: &[u32]) -> Result<Option<u32>> {
        let curr = self.prog[self.pc];
        info!("Executing line {}: {:?}", self.pc, curr);

        self.pc += 1;

        let inst = curr.code & 0x7; // Instruction ("class")
        let size = curr.code & 0x18; // Target size
        let mode = (curr.code & 0xe0) as u32; // Target
        let op = curr.code & 0xf0; // ALU/JMP op
        let src = curr.code & 0x08; // K or idx

        info!("Executing instruction {}", inst);
        match inst as u32 {
            libc::BPF_LD => {
                self.acc = match mode {
                    libc::BPF_IMM => curr.k,
                    libc::BPF_ABS => fetch_data(data, curr.k as usize, size)?,
                    libc::BPF_IND => fetch_data(data, (self.idx + curr.k) as usize, size)?,
                    libc::BPF_MEM => self.mem[curr.k as usize],
                    libc::BPF_LEN => data.len() as u32,
                    _ => return Err(Error::InvalidInstructionCode(curr.code)),
                };
                info!("Loaded value {} into ACC", self.acc);
            }
            libc::BPF_LDX => {
                self.idx = match mode {
                    libc::BPF_IMM => curr.k,
                    libc::BPF_MEM => self.mem[curr.k as usize],
                    libc::BPF_LEN => data.len() as u32,
                    _ => return Err(Error::InvalidInstructionCode(curr.code)),
                };
                info!("Loaded value {} into IDX", self.idx);
            }
            libc::BPF_ST => {
                self.mem[curr.k as usize] = self.acc;
            }
            libc::BPF_STX => {
                self.mem[curr.k as usize] = self.idx;
            }
            libc::BPF_ALU => {
                let sval = self.fetch_src(src, &curr)?;
                self.acc = match op as u32 {
                    libc::BPF_ADD => {
                        info!("Executing ADD with {}", sval);
                        self.acc + sval
                    }
                    libc::BPF_SUB => {
                        info!("Executing SUB with {}", sval);
                        self.acc - sval
                    }
                    libc::BPF_MUL => {
                        info!("Executing MUL with {}", sval);
                        self.acc * sval
                    }
                    libc::BPF_DIV => {
                        info!("Executing DIV with {}", sval);
                        self.acc / sval
                    }
                    libc::BPF_OR => {
                        info!("Executing OR with {}", sval);
                        self.acc | sval
                    }
                    libc::BPF_AND => {
                        info!("Executing AND with {}", sval);
                        self.acc & sval
                    }
                    libc::BPF_LSH => {
                        info!("Executing LSH with {}", sval);
                        self.acc << sval
                    }
                    libc::BPF_RSH => {
                        info!("Executing RSH with {}", sval);
                        self.acc >> sval
                    }
                    libc::BPF_MOD => {
                        info!("Executing MOD  with {}", sval);
                        self.acc % sval
                    }
                    libc::BPF_XOR => {
                        info!("Executing XOR with {}", sval);
                        self.acc ^ sval
                    }
                    libc::BPF_NEG => {
                        error!("NEG is not supported");
                        return Err(Error::UnsupportedInstruction(libc::BPF_NEG as u16));
                    }
                    _ => return Err(Error::UnknownInstruction(inst)),
                };
            }
            libc::BPF_JMP => {
                match op as u32 {
                    libc::BPF_JA => {
                        info!("JA with {}", curr.k);
                        self.pc += curr.k as usize;
                    }
                    libc::BPF_JEQ => {
                        if self.acc == curr.k {
                            info!("JEQ: {} == {} -> {}", self.acc, curr.k, curr.jt);
                            self.pc += curr.jt as usize;
                        } else {
                            info!("JEQ: {} != {} -> {}", self.acc, curr.k, curr.jf);
                            self.pc += curr.jf as usize;
                        }
                    }
                    libc::BPF_JGT => {
                        if self.acc > curr.k {
                            info!("JGT: {} > {} -> {}", self.acc, curr.k, curr.jt);
                            self.pc += curr.jt as usize;
                        } else {
                            info!("JGT: {} ! > {} -> {}", self.acc, curr.k, curr.jf);
                            self.pc += curr.jf as usize;
                        }
                    }
                    libc::BPF_JGE => {
                        if self.acc >= curr.k {
                            info!("JGE: {} >= {} -> {}", self.acc, curr.k, curr.jt);
                            self.pc += curr.jt as usize;
                        } else {
                            info!("JGE: {} ! >= {} -> {}", self.acc, curr.k, curr.jf);
                            self.pc += curr.jf as usize;
                        }
                    }
                    libc::BPF_JSET => {
                        if (self.acc & curr.k) > 0 {
                            info!("JGE: {} & {} -> {}", self.acc, curr.k, curr.jt);
                            self.pc += curr.jt as usize;
                        } else {
                            info!("JGE: {} ! & {} -> {}", self.acc, curr.k, curr.jf);
                            self.pc += curr.jf as usize;
                        }
                    }
                    _ => return Err(Error::UnknownInstruction(inst)),
                };
            }
            libc::BPF_RET => {
                let rsrc = curr.code & 0x18;
                let sval = self.fetch_src(rsrc, &curr)?;
                info!("Executing RET with {}", sval);
                return Ok(Some(sval));
            }
            libc::BPF_MISC => return Err(Error::UnsupportedInstruction(inst)),
            _ => return Err(Error::UnknownInstruction(inst)),
        }

        Ok(None)
    }

    pub fn run(&mut self, data: &[u32]) -> Result<u32> {
        info!("Starting VM");

        self.reset()?;

        while self.pc < self.prog.len() {
            if let Some(r) = self.execute(data)? {
                info!("execute() returned value {}; terminating", r);
                return Ok(r);
            }
        }

        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log;

    fn bpf_stmt(code: u32, val: u32) -> sock_filter {
        sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k: val,
        }
    }
    fn bpf_jmp(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
        sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        }
    }

    #[test_log::test]
    fn test_ret() {
        let prog = vec![bpf_stmt(libc::BPF_RET | libc::BPF_K, 99)];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_load_and_ret() {
        let prog = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_K, 99),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_load_data() {
        let prog = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 1),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![0, 0xFFFFFFFF];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 0xFFFFFFFF);
    }

    #[test_log::test]
    fn test_alu_mask() {
        let prog = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 2),
            bpf_stmt(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0xF0),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
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
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 2),
            bpf_stmt(libc::BPF_ALU | libc::BPF_MUL | libc::BPF_K, 2),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();

        let data = vec![0, 0, 8, 0];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 16);
    }

    #[test_log::test]
    fn test_ld_ja_ret() {
        let prog = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_K, 99),
            bpf_stmt(libc::BPF_JMP | libc::BPF_JA, 1),
            // Should skip this one
            bpf_stmt(libc::BPF_LD | libc::BPF_K, 999),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_ld_gt_ret() {
        let prog = vec![
            bpf_stmt(libc::BPF_LD | libc::BPF_K, 99),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JGT, 98, 1, 0),
            // Should skip this one
            bpf_stmt(libc::BPF_LD | libc::BPF_K, 999),
            bpf_stmt(libc::BPF_RET | BPF_A, 0),
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    fn any_as_u32_slice<T: Sized>(p: &T) -> &[u32] {
        unsafe {
            ::std::slice::from_raw_parts(
                (p as *const T) as *const u32,
                ::std::mem::size_of::<T>(),
            )
        }
    }

    #[test_log::test]
    fn test_seccomp_data_conv() {

        let sc_data = libc::seccomp_data {
            nr: 1,
            arch: 2,
            instruction_pointer: 3,
            args: [4,5,6,7,8,9]
        };
        let data = any_as_u32_slice(&sc_data);

        let prog = vec! [
            // NR
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 0),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 1, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 100),

            // arch
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 1),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 2, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 101),

            // inst_ptr
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 2),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 3, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 102),

            // args[0] = [0, 4]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 3),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 103),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 4),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 4, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 104),

            // args[0] = [0, 5]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 5),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 105),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 6),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 5, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 106),

            // args[0] = [0, 6]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 7),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 107),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 8),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 6, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 108),

            // args[0] = [0, 7]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 9),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 109),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 10),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 7, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 110),

            // args[0] = [0, 8]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 11),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 111),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 12),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 8, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 112),

            // args[0] = [0, 9]
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 13),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 0, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 113),
            bpf_stmt(libc::BPF_LD | libc::BPF_ABS | libc::BPF_W, 14),
            bpf_jmp(libc::BPF_JMP | libc::BPF_JEQ, 9, 1, 0),
            bpf_stmt(libc::BPF_RET | libc::BPF_K, 114),


            bpf_stmt(libc::BPF_RET | libc::BPF_K, 0),

        ];
        let mut vm = BpfVM::new(prog).unwrap();


        let ret = vm.run(&data).unwrap();
        assert!(ret == 0, "Failed, ret = {}", ret);
    }

}