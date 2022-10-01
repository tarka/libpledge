

// See <linux-src>/include/uapi/linux/audit.h
pub const AUDIT_ARCH_64BIT: u32 = 0x80000000;
pub const AUDIT_ARCH_LE: u32 = 0x40000000;
pub const EM_X86_64: u32 = 62;
pub const EM_AARCH64: u32 = 183;

pub const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
pub const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;


// See /usr/include/linux/seccomp.h
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000; /* kill the process */
pub const SECCOMP_RET_KILL_THREAD : u32 = 0x00000000; /* kill the thread */
pub const SECCOMP_RET_KILL        : u32 = SECCOMP_RET_KILL_THREAD;
pub const SECCOMP_RET_TRAP        : u32 = 0x00030000; /* disallow and force a SIGSYS */
pub const SECCOMP_RET_ERRNO       : u32 = 0x00050000; /* returns an errno */
pub const SECCOMP_RET_USER_NOTIF  : u32 = 0x7fc00000; /* notifies userspace */
pub const SECCOMP_RET_TRACE       : u32 = 0x7ff00000; /* pass to a tracer or disallow */
pub const SECCOMP_RET_LOG         : u32 = 0x7ffc0000; /* allow after logging */
pub const SECCOMP_RET_ALLOW       : u32 = 0x7fff0000; /* allow */

/* Masks for the return value sections. */
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff0000;
pub const SECCOMP_RET_ACTION     : u32 = 0x7fff0000;
pub const SECCOMP_RET_DATA       : u32 = 0x0000ffff;
