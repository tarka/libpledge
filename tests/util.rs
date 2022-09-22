
use nix::{unistd::{fork, ForkResult}, sys::{wait::{waitpid, WaitStatus}, signal::Signal}};

pub fn fork_expect_code(expected: i32, childfn: fn()) {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Exited(p2, code) => {
                assert!(p2 == pid);
                assert!(code == expected);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        childfn();
    }
}

pub fn fork_expect_sig(expected: Signal, childfn: fn()) {
    let r = unsafe { fork() }.unwrap();
    if let ForkResult::Parent { child: pid } = r {
        let ret = waitpid(pid, None).unwrap();
        match ret {
            WaitStatus::Signaled(p2, sig, _) => {
                assert!(p2 == pid);
                assert!(sig == expected);
            },
            _ => assert!(false, "Wrong return: {:?}", ret)
        }

    } else {
        childfn();
    }

}
