#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

use nexus_rt::println;

/// Simple FNV-1a hash implementation
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Simple djb2 hash implementation
fn djb2_hash(data: &[u8]) -> u64 {
    let mut hash = 5381u64;
    for byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
    }
    hash
}

/// Simple SDBM hash implementation
fn sdbm_hash(data: &[u8]) -> u64 {
    let mut hash = 0u64;
    for byte in data {
        hash = (*byte as u64)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
    }
    hash
}

/// MurmurHash-inspired simple hash
fn simple_murmur_hash(data: &[u8]) -> u64 {
    const C1: u64 = 0xcc9e2d51;
    const C2: u64 = 0x1b873593;
    const SEED: u64 = 0x9747b28c;

    let mut hash = SEED;

    for byte in data {
        let mut k = *byte as u64;
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);
    }

    // Final avalanche
    hash ^= data.len() as u64;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash
}

#[nexus_rt::main]
fn main() {
    println!("Simple Hash Function Test Suite");
    println!("===============================");

    // Test data
    let test_strings = [
        "hello",
        "world",
        "rust",
        "programming",
        "nexus",
        "zkvm",
        "hash",
        "function",
        "test",
        "data",
        "distribution",
        "algorithm",
        "performance",
        "benchmark",
        "cryptography",
        "security",
    ];

    // Performance test
    println!("\nPerformance Test:");
    println!("=================");

    let large_data = "The quick brown fox jumps over the lazy dog. This is a longer string for performance testing of hash functions.";
    let bytes = large_data.as_bytes();
    let n = 1; // Number of iterations for performance test

    println!("Hashing {} bytes {}) times...", bytes.len(), n);

    let mut results = [0u64; 4];
    for _ in 0..n {
        results[0] = fnv1a_hash(bytes);
        results[1] = djb2_hash(bytes);
        results[2] = sdbm_hash(bytes);
        results[3] = simple_murmur_hash(bytes);
    }

    println!("Final hash results:");
    println!("  FNV-1a: 0x{:016x}", results[0]);
    println!("  djb2:   0x{:016x}", results[1]);
    println!("  SDBM:   0x{:016x}", results[2]);
    println!("  Murmur: 0x{:016x}", results[3]);

    println!("Simple Hash Function test completed successfully!");
}
