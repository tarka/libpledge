pub mod bpf;
mod errors;
pub mod seccomp;
mod vm;

use libc::sock_filter;
pub type BPFProg = Vec<sock_filter>;
pub type RunData<'a> = &'a [u32];

pub use errors::{Error, Result};
pub use vm::{any_to_data, BpfVM};
