use crate::*;

use crate::vm::trace;

#[test]
fn test_trace() {
    let mut vm = nop_vm(0);
    let trace = trace::trace(&mut vm, 100, false).unwrap();
    assert_eq!(trace.k, 100);
    assert_eq!(trace.start, 0);
    assert_eq!(trace.blocks.len(), 1);
    assert_eq!(trace.blocks[0].steps.len(), 100);

    let mut vm = nop_vm(10);
    let trace = trace::trace(&mut vm, 1, true).unwrap();
    assert_eq!(trace.k, 1);
    assert_eq!(trace.start, 0);
    assert_eq!(trace.blocks.len(), 16);
    assert_eq!(trace.blocks[0].steps.len(), 1);

    let mut vm = nop_vm(15);
    let trace = trace::trace(&mut vm, 1, true).unwrap();
    assert_eq!(trace.k, 1);
    assert_eq!(trace.start, 0);
    assert_eq!(trace.blocks.len(), 16);
    assert_eq!(trace.blocks[0].steps.len(), 1);
}
