# bpfvm: A cBPF 'assembler' and virtual machine

`bpfvm` is a small BPF VM implementation and cBPF token 'assembler'. It is
intended for testing cBPF functionality before deployment, e.g. seccomp BPF
filters.

## Example

```rust
// Simple BPF opcode list
//
#[test_log::test]
fn test_alu_mask() {
    let prog = vec![
        bpf_ld(Mode::ABS, 2*WORDS),
        bpf_stmt(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, 0xF0),
        bpf_ret(Src::Acc, 0),
    ];
    let mut vm = BpfVM::new(&prog).unwrap();

    let data = vec![0, 0, 0xFF, 0];
    let ret = vm.run(&data).unwrap();
    assert!(ret == 0xF0);

    let data = vec![0, 0, 0x80, 0];
    let ret = vm.run(&data).unwrap();
    assert!(ret == 0x80);
}

// With tokens and assembler...
//
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

```
