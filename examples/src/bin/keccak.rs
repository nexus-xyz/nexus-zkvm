// This example shows how to compute keccak hashes in software. In
// practice, using a keccak "pre-compile" will be more efficient.

#![cfg_attr(target_arch = "riscv32", no_std, no_main)]
#![allow(non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use nexus_rt::{print, println};

#[inline]
fn rotl64(x: u64, y: u32) -> u64 {
    x.rotate_left(y)
}

fn sha3_keccakf(st: &mut [u64; 25]) {
    const keccakf_rndc: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const keccakf_rotc: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const keccakf_piln: [u32; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    for r in 0..24 {
        // Theta
        let mut bc: [u64; 5] = [0; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for i in 0..5 {
            let t: u64 = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for j in [0, 5, 10, 15, 20] {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        let mut t: u64 = st[1];
        for i in 0..24 {
            let j: u32 = keccakf_piln[i];
            bc[0] = st[j as usize];
            st[j as usize] = rotl64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for j in [0, 5, 10, 15, 20] {
            for i in 0..5 {
                bc[i] = st[j + i];
            }
            for i in 0..5 {
                st[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }
}

// SHA3 API

struct Sha3 {
    pt: i32,
    rsiz: i32,
    mdlen: i32,
    data: Data,
}
union Data {
    b: [u8; 200],
    q: [u64; 25],
}

fn sha3_init(mdlen: i32) -> Sha3 {
    Sha3 {
        pt: 0,
        rsiz: 200 - 2 * mdlen,
        mdlen,
        data: Data { q: [0; 25] },
    }
}

fn sha3_update(c: &mut Sha3, data: &[u8]) {
    let len = data.len();

    let mut j = c.pt;
    for i in 0..len {
        unsafe {
            c.data.b[j as usize] ^= data[i];
        }
        j += 1;
        if j >= c.rsiz {
            unsafe {
                sha3_keccakf(&mut c.data.q);
            }
            j = 0;
        }
    }
    c.pt = j;
}

fn ethash_final(c: &mut Sha3) -> Vec<u8> {
    unsafe {
        c.data.b[c.pt as usize] ^= 0x01; // SHA3 uses 0x06
        c.data.b[(c.rsiz - 1) as usize] ^= 0x80;
        sha3_keccakf(&mut c.data.q);
    }

    let mut v = Vec::new();
    for i in 0..c.mdlen {
        unsafe {
            v.push(c.data.b[i as usize]);
        }
    }
    v
}

fn ethash(bytes: &[u8]) {
    let mut c = sha3_init(32);
    sha3_update(&mut c, bytes);
    let v = ethash_final(&mut c);
    for b in v {
        print!("{b:x}");
    }
    println!();
}

#[nexus_rt::main]
fn main() {
    ethash(b"Hello, World!")
}
