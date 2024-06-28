//! A set of small test machines.

#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::identity_op)]

use super::{memory::Memory, rv32::SOP};
use crate::{NexusVM, Regs};

/// An array of test machines, useful for debugging and developemnt.
#[allow(clippy::type_complexity)]
pub const MACHINES: &[(&str, fn() -> Vec<u32>, fn() -> Regs)] = &[
    ("nop10", || nop_code(10), || nop_result(10)),
    ("loop10", || loop_code(10), || loop_result(10)),
    ("fib31", fib31_code, fib31_result),
    ("bitop", bitop_code, bitop_result),
    ("branch", branch_code, branch_result),
    ("jump", jump_code, jump_result),
    ("ldst", ldst_code, ldst_result),
    ("shift", shift_code, shift_result),
    ("sub", sub_code, sub_result),
];

/// Lookup and initialize a test VM by name
pub fn lookup_test_machine<M: Memory>(name: &str) -> Option<NexusVM<M>> {
    Some(assemble(&lookup_test_code(name)?))
}

/// Lookup a test code sequence by name
pub fn lookup_test_code(name: &str) -> Option<Vec<u32>> {
    for (n, f, _) in MACHINES {
        if *n == name {
            return Some(f());
        }
    }
    None
}

fn assemble<M: Memory>(words: &[u32]) -> NexusVM<M> {
    let mut vm = NexusVM::<M>::new(0);
    for (i, w) in words.iter().enumerate() {
        vm.mem
            .store(SOP::SW, i as u32 * 4, *w, i as u32 * 4)
            .unwrap();
    }
    vm
}

/// Create a VM with k no-op instructions
pub fn nop_vm<M: Memory>(k: usize) -> NexusVM<M> {
    assemble(&nop_code(k))
}

/// Create an instruction sequence with k no-op instructions
pub fn nop_code(k: usize) -> Vec<u32> {
    let mut v = vec![0x13; k];
    v.push(0xc0001073); // unimp
    v
}

fn nop_result(k: usize) -> Regs {
    Regs { pc: k as u32 * 4, ..Regs::default() }
}

/// Create a VM which loops k times
pub fn loop_vm<M: Memory>(k: usize) -> NexusVM<M> {
    assemble(&loop_code(k))
}

/// Create an instruction sequence which loops k times
pub fn loop_code(k: usize) -> Vec<u32> {
    assert!(k < (1 << 31));
    let hi = (k as u32) & 0xfffff000;
    let lo = ((k & 0xfff) << 20) as u32;

    vec![
        hi | 0x137,   // lui x2, hi
        lo | 0x10113, // addi x2, x2, lo
        0x00000093,   // li x1, 0
        0x00108093,   // addi x1, x1, 1
        0xfe209ee3,   // bne x1, x2, 0x100c
        0xc0001073,   // unimp
    ]
}

fn loop_result(k: usize) -> Regs {
    let k = k as u32;
    let mut regs = Regs::default();
    regs.x[1] = k;
    regs.x[2] = k;
    regs.pc = 5 * 4;
    regs
}

// Compute fib(n) in register n (for n in 0..32).
// The highest register, x31, will be equal to fib(31).
fn fib31_code() -> Vec<u32> {
    vec![
        0x00100093, //  addi x1,x0,1
        0x00008133, //  add  x2,x1,x0
        0x001101b3, //  add  x3,x2,x1
        0x00218233, //  add  x4,x3,x2
        0x003202b3, //  add  x5,x4,x3
        0x00428333, //  add  x6,x5,x4
        0x005303b3, //  add  x7,x6,x5
        0x00638433, //  add  x8,x7,x6
        0x007404b3, //  add  x9,x8,x7
        0x00848533, //  add  x10,x9,x8
        0x009505b3, //  add  x11,x10,x9
        0x00a58633, //  add  x12,x11,x10
        0x00b606b3, //  add  x13,x12,x11
        0x00c68733, //  add  x14,x13,x12
        0x00d707b3, //  add  x15,x14,x13
        0x00e78833, //  add  x16,x15,x14
        0x00f808b3, //  add  x17,x16,x15
        0x01088933, //  add  x18,x17,x16
        0x011909b3, //  add  x19,x18,x17
        0x01298a33, //  add  x20,x19,x18
        0x013a0ab3, //  add  x21,x20,x19
        0x014a8b33, //  add  x22,x21,x20
        0x015b0bb3, //  add  x23,x22,x21
        0x016b8c33, //  add  x24,x23,x22
        0x017c0cb3, //  add  x25,x24,x23
        0x018c8d33, //  add  x26,x25,x24
        0x019d0db3, //  add  x27,x26,x25
        0x01ad8e33, //  add  x28,x27,x26
        0x01be0eb3, //  add  x29,x28,x27
        0x01ce8f33, //  add  x30,x29,x28
        0x01df0fb3, //  add  x31,x30,x29
        0xc0001073, // unimp
    ]
}

// Expected result of running the fib31 VM.
fn fib31_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 31 * 4;
    regs.x[1] = 1;
    for i in 2..32 {
        regs.x[i] = regs.x[i - 1] + regs.x[i - 2];
    }
    regs
}

// Tests of the bitwise operators.
pub fn bitop_code() -> Vec<u32> {
    vec![
        0xaaaab0b7, //  lui     x1,0xaaaab
        0xfaa08093, //  addi    x1,x1,-86 # aaaaafaa
        0x55555137, //  lui     x2,0x55555
        0x55510113, //  addi    x2,x2,1365 # 55555555
        0x0020f1b3, //  and     x3,x1,x2
        0x0ff0f213, //  andi    x4,x1,255
        0x0020e2b3, //  or      x5,x1,x2
        0x0ff0e313, //  ori     x6,x1,255
        0x0020c3b3, //  xor     x7,x1,x2
        0x0ff0c413, //  xori    x8,x1,255
        0xc0001073, //  unimp
    ]
}

// Expected result of running the bitop VM.
fn bitop_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 10 * 4;
    regs.x[1] = 0xaaaaafaa;
    regs.x[2] = 0x55555555;
    regs.x[3] = regs.x[1] & regs.x[2];
    regs.x[4] = regs.x[1] & 255;
    regs.x[5] = regs.x[1] | regs.x[2];
    regs.x[6] = regs.x[1] | 255;
    regs.x[7] = regs.x[1] ^ regs.x[2];
    regs.x[8] = regs.x[1] ^ 255;
    regs
}

// Test the branch instructions.
fn branch_code() -> Vec<u32> {
    vec![
        0x00100093, //  addi    x1,x0,1
        0x00200113, //  addi    x2,x0,2
        0x00208663, //  beq     x1,x2,14
        0x00108463, //  beq     x1,x1,14
        0xc0001073, //  unimp
        0x00109663, //  bne     x1,x1,20
        0x00209463, //  bne     x1,x2,20
        0xc0001073, //  unimp
        0xfff00193, //  addi    x3,x0,-1
        0x00114863, //  blt     x2,x1,34
        0x0030c663, //  blt     x1,x3,34
        0x0011c463, //  blt     x3,x1,34
        0xc0001073, //  unimp
        0x0001d863, //  bge     x3,x0,44
        0x0020d663, //  bge     x1,x2,44
        0x00315463, //  bge     x2,x3,44
        0xc0001073, //  unimp
        0x00116863, //  bltu    x2,x1,54
        0x0001e663, //  bltu    x3,x0,54
        0x00316463, //  bltu    x2,x3,54
        0xc0001073, //  unimp
        0x00307863, //  bgeu    x0,x3,64
        0x00317663, //  bgeu    x2,x3,64
        0x0031f463, //  bgeu    x3,x3,64
        0xc0001073, //  unimp
        0x00100513, //  addi    x10,x0,1
        0x00100593, //  addi    x11,x0,1
        0xc0001073, // unimp
    ]
}

// Expected result of running the branch VM.
fn branch_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 27 * 4;
    regs.x[1] = 1;
    regs.x[2] = 2;
    regs.x[3] = -1i32 as u32;
    regs.x[10] = 1;
    regs.x[11] = 1;
    regs
}

// Test the jump instructions.
fn jump_code() -> Vec<u32> {
    vec![
        0x008000ef, // jal     x1,08
        0xc0001073, // unimp
        0x008000ef, // jal     x1,10
        0xc0001073, // unimp
        0x0080016f, // jal     x2,18
        0xc0001073, // unimp
        0x00000097, // auipc   x1,0x0
        0x00c081e7, // jalr    x3,12(x1) # 24
        0xc0001073, // unimp
        0xfe1ff06f, // jal     x0,04
        0xc0001073, // unimp
    ]
}

// Expected result of running the jump VM.
fn jump_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 4;
    regs.x[1] = 6 * 4;
    regs.x[2] = 5 * 4;
    regs.x[3] = 8 * 4;
    regs
}

// Test the load and store instructions.
fn ldst_code() -> Vec<u32> {
    vec![
        0xfff00293, //  addi    x5,x0,-1
        0x00502223, //  sw      x5,4(x0)
        0x005000a3, //  sb      x5,1(x0)
        0xfe502e23, //  sw      x5,-4(x0)
        0x00402083, //  lw      x1,4(x0)
        0xffc02103, //  lw      x2,-4(x0)
        0x00100183, //  lb      x3,1(x0)
        0x00104203, //  lbu     x4,1(x0)
        0xc0001073, //  unimp
    ]
}

// Expected result of running the ldst VM.
fn ldst_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 8 * 4;
    regs.x[1] = -1i32 as u32;
    regs.x[2] = -1i32 as u32;
    regs.x[3] = -1i32 as u32;
    regs.x[4] = 255;
    regs.x[5] = -1i32 as u32;
    regs
}

// Test the shift instructions.
fn shift_code() -> Vec<u32> {
    vec![
        0xfaaab0b7, //  lui     x1,0xfaaab
        0xaaa08093, //  addi    x1,x1,-1366 # faaaaaaa
        0x00500113, //  addi    x2,x0,5
        0x002091b3, //  sll     x3,x1,x2
        0x0020d233, //  srl     x4,x1,x2
        0x4020d2b3, //  sra     x5,x1,x2
        0x00009313, //  slli    x6,x1,0x0
        0x00109393, //  slli    x7,x1,0x1
        0x00a09413, //  slli    x8,x1,0xa
        0x01f09493, //  slli    x9,x1,0x1f
        0x0000d513, //  srli    x10,x1,0x0
        0x0010d593, //  srli    x11,x1,0x1
        0x00a0d613, //  srli    x12,x1,0xa
        0x01f0d693, //  srli    x13,x1,0x1f
        0x4000d713, //  srai    x14,x1,0x0
        0x4010d793, //  srai    x15,x1,0x1
        0x40a0d813, //  srai    x16,x1,0xa
        0x41f0d893, //  srai    x17,x1,0x1f
        0xc0001073, //  unimp
    ]
}

// Expected result of running the shift VM.
fn shift_result() -> Regs {
    fn sra(x: u32, y: u32) -> u32 {
        ((x as i32) >> y) as u32
    }

    let mut regs = Regs::default();
    regs.pc = 18 * 4;
    regs.x[1] = 0xfaaaaaaa;

    regs.x[2] = 5;
    regs.x[3] = regs.x[1] << regs.x[2];
    regs.x[4] = regs.x[1] >> regs.x[2];
    regs.x[5] = sra(regs.x[1], regs.x[2]);

    regs.x[6] = regs.x[1] << 0;
    regs.x[7] = regs.x[1] << 0x1;
    regs.x[8] = regs.x[1] << 0xa;
    regs.x[9] = regs.x[1] << 0x1f;

    regs.x[10] = regs.x[1] >> 0;
    regs.x[11] = regs.x[1] >> 0x1;
    regs.x[12] = regs.x[1] >> 0xa;
    regs.x[13] = regs.x[1] >> 0x1f;

    regs.x[14] = sra(regs.x[1], 0);
    regs.x[15] = sra(regs.x[1], 0x1);
    regs.x[16] = sra(regs.x[1], 0xa);
    regs.x[17] = sra(regs.x[1], 0x1f);

    regs
}

// Test the subtraction and compare instructions.
fn sub_code() -> Vec<u32> {
    vec![
        0x00100093, //  addi    x1,x0,1
        0xfff00113, //  addi    x2,x0,-1
        0x40008233, //  sub     x4,x1,x0
        0x40208233, //  sub     x4,x1,x2
        0x40110233, //  sub     x4,x2,x1
        0x0000a233, //  slt     x4,x1,x0
        0x04021463, //  bne     x4,x0,60
        0x00102233, //  slt     x4,x0,x1
        0x04020063, //  beq     x4,x0,60
        0x00112233, //  slt     x4,x2,x1
        0x02020c63, //  beq     x4,x0,60
        0x00113233, //  sltu    x4,x2,x1
        0x02021863, //  bne     x4,x0,60
        0x00112213, //  slti    x4,x2,1
        0x02020463, //  beq     x4,x0,60
        0xffd12213, //  slti    x4,x2,-3
        0x02021063, //  bne     x4,x0,60
        0x00113213, //  sltiu   x4,x2,1
        0x00021c63, //  bne     x4,x0,60
        0xffd13213, //  sltiu   x4,x2,-3
        0x00021863, //  bne     x4,x0,60
        0xfff0b213, //  sltiu   x4,x1,-1
        0x00020463, //  beq     x4,x0,60
        0x00100513, //  addi    x10,x0,1
        0xc0001073, //  unimp
    ]
}

// Expected result of running the sub VM.
fn sub_result() -> Regs {
    let mut regs = Regs::default();
    regs.pc = 24 * 4;
    regs.x[1] = 1;
    regs.x[2] = -1i32 as u32;
    regs.x[4] = 1;
    regs.x[10] = 1;
    regs
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::eval;
    use crate::trie::MerkleTrie;

    #[test]
    fn test_machines() {
        for (name, f_code, f_result) in MACHINES {
            println!("Testing machine {name}");
            let mut vm: NexusVM<MerkleTrie> = assemble(&f_code());
            eval(&mut vm, false).unwrap();
            let regs = f_result();
            assert_eq!(regs, vm.regs);
        }
    }
}
