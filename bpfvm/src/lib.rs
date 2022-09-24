mod errors;

use libc::sock_filter;
use log::{error, info};

use crate::errors::{Error, Result};

type fprog = Vec<sock_filter>;
const MEMSIZE: usize = libc::BPF_MEMWORDS as usize;
const BPF_A: u32 = 0x10;  // Not defined in libc for some reason.

pub struct BpfVM {
    pub counter: usize,
    pub acc: u32,
    pub idx: u32,
    pub mem: [u32; MEMSIZE],
    pub prog: Vec<sock_filter>,
}


fn fetch_u32(data: &[u8], off: usize) -> Result<u32> {
    let s = &data[off..off+4];
    let w = u32::from_be_bytes(s.try_into()?);
    Ok(w)
}

fn fetch_u16(data: &[u8], off: usize) -> Result<u32> {
    let s = &data[off..off+2];
    let w = u16::from_be_bytes(s.try_into()?);
    Ok(w as u32)
}

fn fetch_u8(data: &[u8], off: usize) -> Result<u32> {
    Ok(data[off] as u32)
}

fn fetch_data(data: &[u8], off: usize, size: u16) -> Result<u32> {
    match size as u32 {
        libc::BPF_W => {
            fetch_u32(data, off)
        },
        libc::BPF_H => {
            fetch_u16(data, off)
        },
        libc::BPF_B => {
            fetch_u8(data, off)
        },
        _ => return Err(Error::InvalidInstructionCode(size)),
    }
}

impl BpfVM {

    pub fn new(prog: fprog) -> Result<BpfVM> {
        if prog.len() > u16::MAX as usize {
            return Err(Error::ProgramTooLong(prog.len()));
        }

        Ok(BpfVM {
            counter: 0,
            acc: 0,
            idx: 0,
            mem: [0; MEMSIZE],
            prog: prog.clone(),
        })
    }

    pub fn reset(& mut self) -> Result<()> {
        self.counter = 0;
        self.acc = 0;
        self.idx = 0;
        self.mem = [0; MEMSIZE];
        Ok(())
    }

    fn fetch_src(&self, src: u16, curr: &sock_filter) -> Result<u32> {
        match src as u32{
            libc::BPF_K => {
                info!("Src is K: {}", curr.k);
                return Ok(curr.k)
            },
            libc::BPF_X => {
                info!("Src is IDX: {}", self.idx);
                return Ok(self.idx)
            },
            BPF_A => {
                info!("Src is ACC: {}", self.acc);
                return Ok(self.acc)
            },
            _ => return Err(Error::InvalidInstructionCode(curr.code))
        }
    }

    pub fn execute(& mut self, data: &[u8]) -> Result<Option<u32>> {
        let curr = self.prog[self.counter];
        info!("Executing line {}: {:?}", self.counter, curr);

        self.counter += 1;

        let inst = curr.code & 0x7;  // Instruction ("class")
        let size = curr.code & 0x18; // Target size
        let mode = (curr.code & 0xe0) as u32; // Target
        let op = curr.code & 0xf0;   // ALU/JMP op
        let src = curr.code & 0x08;  // K or idx

        info!("Executing instruction {}", inst);
        match inst as u32 {
            libc::BPF_LD => {
                self.acc = match mode {
		    libc::BPF_IMM => {
                        curr.k
                    },
		    libc::BPF_ABS => {
                        fetch_data(data, curr.k as usize, size)?
                    },
		    libc::BPF_IND => {
                        fetch_data(data, (self.idx + curr.k) as usize, size)?
                    },
		    libc::BPF_MEM => {
                        self.mem[curr.k as usize]
                    },
		    libc::BPF_LEN => {
                        data.len() as u32
                    },
                    _ => return Err(Error::InvalidInstructionCode(curr.code))
                };
                info!("Loaded value {} into ACC", self.acc);
            },
            libc::BPF_LDX => {
                self.idx = match mode {
		    libc::BPF_IMM => {
                        curr.k
                    },
		    libc::BPF_MEM => {
                        self.mem[curr.k as usize]
                    },
		    libc::BPF_LEN => {
                        data.len() as u32
                    },
                    _ => return Err(Error::InvalidInstructionCode(curr.code))
                };
                info!("Loaded value {} into IDX", self.idx);
            },
            libc::BPF_ST => {
                self.mem[curr.k as usize] = self.acc;
            },
            libc::BPF_STX => {
                self.mem[curr.k as usize] = self.idx;
            },
            libc::BPF_ALU => {
                let sval = self.fetch_src(src, &curr)?;
                self.acc = match op as u32 {
		    libc::BPF_ADD => {
                        info!("Executing ADD with {}", sval);
                        self.acc + sval
                    },
		    libc::BPF_SUB => {
                        info!("Executing SUB with {}", sval);
                        self.acc - sval
                    },
		    libc::BPF_MUL => {
                        info!("Executing MUL with {}", sval);
                        self.acc * sval
                    },
		    libc::BPF_DIV => {
                        info!("Executing DIV with {}", sval);
                        self.acc / sval
                    },
		    libc::BPF_OR => {
                        info!("Executing OR with {}", sval);
                        self.acc | sval
                    },
		    libc::BPF_AND => {
                        info!("Executing AND with {}", sval);
                        self.acc & sval
                    },
		    libc::BPF_LSH => {
                        info!("Executing LSH with {}", sval);
                        self.acc << sval
                    },
		    libc::BPF_RSH => {
                        info!("Executing RSH with {}", sval);
                        self.acc >> sval
                    },
		    libc::BPF_MOD => {
                        info!("Executing MOD  with {}", sval);
                        self.acc % sval
                    },
		    libc::BPF_XOR => {
                        info!("Executing XOR with {}", sval);
                        self.acc ^ sval
                    },
		    libc::BPF_NEG => {
                        error!("NEG is not supported");
                        return Err(Error::UnsupportedInstruction(libc::BPF_NEG as u16))
                    },
                    _ => {
                        return Err(Error::UnknownInstruction(inst))
                    },
                };
            },
            libc::BPF_JMP => {},
            libc::BPF_RET => {
                let rsrc = curr.code & 0x18;
                let sval = self.fetch_src(rsrc, &curr)?;
                info!("Executing RET with {}", sval);
                return Ok(Some(sval))
            },
            libc::BPF_MISC => {
                return Err(Error::UnsupportedInstruction(inst))
            },
            _ => {
                return Err(Error::UnknownInstruction(inst))
            },
        }

        Ok(None)
    }

    pub fn run(& mut self, data: &[u8]) -> Result<u32> {
        info!("Starting VM");

        self.reset()?;

        while self.counter < self.prog.len() {
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
    use test_log;
    use super::*;

    #[test_log::test]
    fn test_ret() {
        let prog = vec! [
            sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 99
            },
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }

    #[test_log::test]
    fn test_load_and_ret() {
        let prog = vec! [
            sock_filter {
                code: (libc::BPF_LD | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 99
            },
            sock_filter {
                code: (libc::BPF_RET | BPF_A) as u16,
                jt: 0,
                jf: 0,
                k: 0
            },
        ];
        let mut vm = BpfVM::new(prog).unwrap();
        let data = vec![];
        let ret = vm.run(&data).unwrap();
        assert!(ret == 99);
    }
}
