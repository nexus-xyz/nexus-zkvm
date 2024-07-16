#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use nexus_rt::{print, println};

fn stable_matching(
    n: usize,
    mut employers: BTreeSet<usize>,
    mut candidates: BTreeSet<usize>,
    employer_prefs: Vec<Vec<usize>>,
    candidate_prefs: Vec<Vec<usize>>,
) -> Vec<Option<usize>> {
    let mut hires: Vec<Option<usize>> = vec![None; n];

    while !employers.is_empty() {
        let next = employers.pop_first().unwrap();
        let prefs = &employer_prefs[next];

        for c in prefs {
            if candidates.contains(c) {
                hires[next] = Some(*c);
                assert!(candidates.remove(c));

                break;
            } else {
                let current = hires
                    .iter()
                    .position(|&x| x.is_some() && *c == x.unwrap())
                    .unwrap();
                if candidate_prefs[*c].iter().position(|&x| next == x)
                    < candidate_prefs[*c].iter().position(|&x| current == x)
                {
                    assert!(employers.insert(current));

                    hires[next] = Some(*c);
                    hires[current] = None;

                    break;
                }
            }
        }
    }

    hires
}

#[nexus_rt::main]
fn main() {
    let n = 10;
    let m = 8;
    assert!(m < n);

    let mut employers = BTreeSet::<usize>::new();
    let mut candidates = BTreeSet::<usize>::new();

    for i in 0..n {
        employers.insert(i);
        if i < m {
            candidates.insert(i);
        }
    }

    let employer_prefs = vec![
        vec![4, 1, 2, 7, 3, 0, 6, 5],
        vec![0, 1, 4, 5, 7, 2, 6, 3],
        vec![3, 7, 4, 6, 2, 0, 5, 1],
        vec![4, 6, 0, 2, 7, 3, 5, 1],
        vec![2, 6, 1, 3, 7, 0, 4, 5],
        vec![1, 4, 5, 3, 7, 0, 6, 2],
        vec![1, 5, 4, 0, 6, 2, 7, 3],
        vec![3, 6, 1, 2, 7, 0, 5, 4],
        vec![7, 5, 3, 4, 1, 6, 2, 0],
        vec![0, 6, 1, 4, 5, 2, 7, 3],
    ];

    let candidate_prefs = vec![
        vec![0, 5, 7, 8, 3, 1, 4, 2, 6, 9],
        vec![8, 2, 0, 9, 3, 4, 5, 6, 1, 7],
        vec![3, 6, 4, 0, 5, 9, 7, 8, 2, 1],
        vec![2, 9, 7, 3, 4, 1, 5, 8, 0, 6],
        vec![7, 5, 9, 4, 6, 8, 0, 1, 3, 2],
        vec![4, 1, 7, 6, 2, 9, 8, 0, 5, 3],
        vec![0, 5, 3, 6, 8, 7, 4, 1, 9, 2],
        vec![7, 5, 6, 1, 4, 0, 2, 8, 9, 3],
    ];

    println!("\nNumber of Employers  = {}", n);
    println!("Number of Candidates = {}", m);
    println!("\nBeginning matching...\n");

    let hires = stable_matching(n, employers, candidates, employer_prefs, candidate_prefs);

    print!("Found matching (employer, candidate): ");
    for i in 0..n {
        if i > 0 {
            print!(", ")
        }
        print!(
            "({}, {})",
            i,
            if hires[i].is_some() {
                hires[i].unwrap().to_string()
            } else {
                "None".to_string()
            }
        );
    }
    println!("\n");
}
