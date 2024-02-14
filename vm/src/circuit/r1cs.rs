//! A direct representation of R1CS over the field F.
//!
//! This crate provides a representation of R1CS as a set of
//! matrices without an intermediate representation of the
//! constraints. The matrices are dense for simplicity, and
//! are over a fixed field.
//! These matrices are meant to be used at compile-time as a
//! source for generating constraints over a target field.

#![allow(clippy::wrong_self_convention)]

// Historical note: this structure was originally used as
// an intermediate structure before translating to either
// bellman or arkworks. In the current code we only support
// arkworks, and perhaps should be rewritten.

use std::collections::HashMap;
use std::ops::Range;

use ark_bn254::FrConfig;
use ark_ff::{BigInt, Fp, MontConfig};

pub use ark_bn254::Fr as F;

pub const ZERO: F = Fp::new(BigInt([0, 0, 0, 0]));
pub const ONE: F = Fp::new(BigInt([1, 0, 0, 0]));
pub const TWO: F = Fp::new(BigInt([2, 0, 0, 0]));
pub const MINUS: F = {
    let BigInt([a, b, c, d]) = FrConfig::MODULUS;
    Fp::new(BigInt([a - 1, b, c, d]))
};

pub type V = Vec<F>;
pub type M = Vec<Vec<F>>;

#[derive(Clone, Debug)]
pub struct R1CS {
    pub w: V,
    pub a: M,
    pub b: M,
    pub c: M,
    pub arity: usize,
    pub witness_only: bool,
    pub(crate) vars: HashMap<String, usize>,
    pub(crate) locals: Vec<String>,
}

impl Default for R1CS {
    fn default() -> Self {
        R1CS {
            w: vec![ONE],
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            arity: 0,
            witness_only: false,
            vars: HashMap::new(),
            locals: Vec::new(),
        }
    }
}

impl R1CS {
    #[inline]
    pub fn input_range(&self) -> Range<usize> {
        Range { start: 1, end: 1 + self.arity }
    }

    #[inline]
    pub fn output_range(&self) -> Range<usize> {
        Range {
            start: 1 + self.arity,
            end: 1 + 2 * self.arity,
        }
    }

    #[inline]
    pub fn input(&self) -> &[F] {
        &self.w[self.input_range()]
    }

    #[inline]
    pub fn output(&self) -> &[F] {
        &self.w[self.output_range()]
    }

    pub fn new_var(&mut self, name: &str) -> usize {
        if let Some(n) = self.vars.get(name) {
            return *n;
        }
        let n = self.w.len();
        self.vars.insert(name.to_string(), n);
        self.w.push(ZERO);
        if !self.a.is_empty() {
            self.a.iter_mut().for_each(|v| v.push(ZERO));
            self.b.iter_mut().for_each(|v| v.push(ZERO));
            self.c.iter_mut().for_each(|v| v.push(ZERO));
        }
        n
    }

    pub fn set_field_var(&mut self, name: &str, val: F) -> usize {
        let j = self.new_var(name);
        self.w[j] = val;
        j
    }

    pub fn set_var(&mut self, name: &str, val: u32) -> usize {
        self.set_field_var(name, F::from(val))
    }

    pub fn new_local_var(&mut self, name: &str) -> usize {
        if self.vars.contains_key(name) {
            panic!("local variable override {name}");
        }
        let n = self.new_var(name);
        self.locals.push(name.to_string());
        n
    }

    pub fn seal(&mut self) {
        for v in &self.locals {
            self.vars.remove(v);
        }
        self.locals.clear();
    }

    pub fn has_var(&self, name: &str) -> bool {
        self.vars.contains_key(name)
    }

    pub fn var(&self, name: &str) -> usize {
        *self.vars.get(name).unwrap()
    }

    pub fn get_var(&self, name: &str) -> &F {
        &self.w[self.var(name)]
    }

    pub fn constraint<F>(&mut self, f: F)
    where
        F: FnOnce(&Self, &mut V, &mut V, &mut V),
    {
        if self.witness_only {
            return;
        }
        let mut a = vec![ZERO; self.w.len()];
        let mut b = a.clone();
        let mut c = a.clone();

        f(self, &mut a, &mut b, &mut c);

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);
    }

    pub fn equal_scalar(&mut self, name: &str, x: F) {
        self.constraint(|cs, a, b, c| {
            a[cs.var(name)] = ONE;
            b[0] = ONE;
            c[0] = x;
        });
    }

    pub fn equal(&mut self, name: &str, val: u32) {
        self.equal_scalar(name, F::from(val))
    }

    pub fn set_eq(&mut self, name: &str, var: &str) -> usize {
        let vj = self.var(var);
        let j = self.new_var(name);
        self.w[j] = self.w[vj];
        self.constraint(|_cs, a, b, c| {
            a[vj] = ONE;
            b[0] = ONE;
            c[j] = ONE;
        });
        j
    }

    pub fn set_bit(&mut self, name: &str, val: bool) -> usize {
        let j = self.new_var(name);
        self.w[j] = if val { ONE } else { ZERO };
        self.constraint(|_cs, a, b, _c| {
            a[0] = MINUS;
            a[j] = ONE;
            b[j] = ONE;
        });
        j
    }

    pub fn not(&mut self, output: &str, input: &str) -> usize {
        let i = self.var(output);
        let j = self.var(input);
        self.constraint(|_cs, a, b, c| {
            a[0] = ONE;
            a[j] = MINUS;
            b[0] = ONE;
            c[i] = ONE;
        });
        i
    }

    pub fn set_not(&mut self, output: &str, input: &str) -> usize {
        self.set_field_var(output, ONE - self.get_var(input));
        self.not(output, input)
    }

    pub fn to_bits(&mut self, name: &str, val: u32) -> usize {
        let vj = self.set_var(name, val);
        let js: Vec<usize> = (0..32)
            .map(|i| self.set_bit(&format!("{name}_{i}"), ((val >> i) & 1) == 1))
            .collect();

        self.constraint(|_cs, a, b, c| {
            for i in 0..32 {
                a[js[i]] = F::from(1u64 << i);
            }
            b[0] = ONE;
            c[vj] = ONE;
        });
        vj
    }

    pub fn from_bits(&mut self, output: &str, val: u32, from: &str, start: u32, end: u32) -> usize {
        let j = self.set_var(output, val);
        self.constraint(|cs, a, b, c| {
            for i in (start..end).rev() {
                a[cs.var(&format!("{from}_{i}"))] = F::from(1u64 << (i - start));
            }
            b[0] = ONE;
            c[j] = ONE;
        });
        j
    }

    pub fn add(&mut self, v0: &str, v1: &str, v2: &str) {
        self.constraint(|cs, a, b, c| {
            a[cs.var(v1)] = ONE;
            a[cs.var(v2)] = ONE;
            b[0] = ONE;
            c[cs.var(v0)] = ONE;
        });
    }

    pub fn set_add(&mut self, v0: &str, v1: &str, v2: &str) {
        self.set_field_var(v0, self.get_var(v1) + self.get_var(v2));
        self.add(v0, v1, v2)
    }

    pub fn addi(&mut self, v0: &str, v1: &str, x: F) {
        self.constraint(|cs, a, b, c| {
            a[0] = x;
            a[cs.var(v1)] = ONE;
            b[0] = ONE;
            c[cs.var(v0)] = ONE;
        });
    }

    pub fn mul(&mut self, v0: &str, v1: &str, v2: &str) {
        self.constraint(|cs, a, b, c| {
            a[cs.var(v1)] = ONE;
            b[cs.var(v2)] = ONE;
            c[cs.var(v0)] = ONE;
        });
    }

    pub fn set_mul(&mut self, v0: &str, v1: &str, v2: &str) {
        self.set_field_var(v0, self.get_var(v1) * self.get_var(v2));
        self.mul(v0, v1, v2)
    }

    pub fn muli(&mut self, v0: &str, v1: &str, x: F) {
        self.constraint(|cs, a, b, c| {
            a[0] = x;
            b[cs.var(v1)] = ONE;
            c[cs.var(v0)] = ONE;
        });
    }

    pub fn merge(&mut self, cs: &Self) {
        let left_len = self.w.len();
        let len = left_len + cs.w.len();
        self.w.extend_from_slice(&cs.w);
        let merge_M = |x: &mut M, y: &M| {
            x.iter_mut().for_each(|r| r.resize(len, ZERO));
            for right in y {
                let mut left = vec![ZERO; left_len];
                left.extend_from_slice(right);
                x.push(left);
            }
        };
        merge_M(&mut self.a, &cs.a);
        merge_M(&mut self.b, &cs.b);
        merge_M(&mut self.c, &cs.c);

        cs.vars.iter().for_each(|(n, i)| {
            self.vars.insert(n.to_string(), left_len + i);
        })
    }

    // note: is_sat is only used in tests, so performance is not
    // too important.
    pub fn is_sat(&self) -> bool {
        assert!(self.a.len() == self.b.len());
        assert!(self.a.len() == self.c.len());

        for m in [&self.a, &self.b, &self.c] {
            for v in m {
                assert!(v.len() == self.w.len());
            }
        }

        fn dot(a: &V, b: &V) -> F {
            a.iter().zip(b).map(|(a, b)| a * b).sum()
        }

        fn multiply_vec(m: &M, v: &V) -> Vec<F> {
            m.iter().map(|r| dot(r, v)).collect()
        }

        let x = multiply_vec(&self.a, &self.w);
        let y = multiply_vec(&self.b, &self.w);
        let z = multiply_vec(&self.c, &self.w);

        for i in 0..x.len() {
            if x[i] * y[i] != z[i] {
                println!("constraint {i} not satisfied");
                println!("A");
                let v = &self.a[i];
                for i in 0..v.len() {
                    if v[i] != ZERO {
                        println!("{} * {}", v[i], self.w[i]);
                    }
                }
                println!("B");
                let v = &self.b[i];
                for i in 0..v.len() {
                    if v[i] != ZERO {
                        println!("{} * {}", v[i], self.w[i]);
                    }
                }
                println!("C");
                let v = &self.c[i];
                for i in 0..v.len() {
                    if v[i] != ZERO {
                        let mut rv = format!("{i}");
                        for (n, j) in &self.vars {
                            if *j == i {
                                rv = n.clone();
                            }
                        }
                        println!("{} * {} (name {})", v[i], self.w[i], rv);
                    }
                }
            }
        }

        (0..x.len()).all(|i| x[i] * y[i] == z[i])
    }
}

pub fn member(cs: &mut R1CS, name: &str, k: u32, set: &[u32]) {
    debug_assert!(set.len() > 1);
    debug_assert!(set.contains(&k));

    // Compute constant that comes from evaulating
    // (x - s0)(x - s1)...(x - s{n - 1}) / (x - sk)
    // at the point sk
    let C = |k: u32| -> F {
        let mut c = ONE;
        for &x in set {
            if x != k {
                c *= F::from(k) - F::from(x);
            }
        }
        c
    };

    // compute witness, starting with input x
    let x = F::from(k);
    let jj = cs.new_var(name);
    cs.w[jj] = x;

    let n = set.len();
    let mut lp = ONE;
    let mut rp = ONE;
    for i in 0..n {
        // (x-si) terms
        let j = cs.new_local_var(&format!("x-{i}"));
        cs.w[j] = x - F::from(set[i]);

        // left products l_i = (x - s0)(x - s1)...(x - si)
        let j = cs.new_local_var(&format!("l{i}"));
        lp *= x - F::from(set[i]);
        cs.w[j] = lp;

        // right products r_n-1-i = (x - s{n-1})(x - s{n-2})...(x - s{n-1-i})
        let i2 = n - 1 - i;
        let j = cs.new_local_var(&format!("r{i2}"));
        rp *= x - F::from(set[i2]);
        cs.w[j] = rp;

        // l_i * r_i = C(i) * (x-s0)...(x-s{i-1}) (x-s{i+1})...(x-s{n-1})
        let j = cs.new_local_var(&format!("cx{i}"));
        cs.w[j] = if set[i] == k { C(set[i]) } else { ZERO };

        // selectors: l_i * r_i / C(i) = 0 or 1
        let j = cs.new_var(&format!("{name}={}", set[i]));
        cs.w[j] = if set[i] == k { ONE } else { ZERO };
    }

    if cs.witness_only {
        cs.seal();
        return;
    }

    // build constraints: l_n-1 = r_0 = 0
    // x(x-s1)...(x-s{n-1}) = 0
    cs.equal_scalar("r0", ZERO);
    cs.equal_scalar(&format!("l{}", n - 1), ZERO);

    for i in 0..n {
        //set x-k variables
        let si = ZERO - F::from(set[i]);
        cs.addi(&format!("x-{i}"), name, si);

        // set lp variables
        if i == 0 {
            cs.muli("l0", "x-0", ONE);
        } else {
            cs.mul(&format!("l{i}"), &format!("l{}", i - 1), &format!("x-{i}"));
        }

        // set rp variables
        if i == n - 1 {
            cs.muli(&format!("r{}", i), &format!("x-{i}"), ONE);
        } else {
            cs.mul(
                &format!("r{}", i),
                &format!("x-{i}"),
                &format!("r{}", i + 1),
            );
        }

        // set cx_i variables
        if i == 0 {
            cs.muli("cx0", "r1", ONE);
        } else if i == (n - 1) {
            cs.muli(&format!("cx{}", i), &format!("l{}", i - 1), ONE);
        } else {
            cs.mul(
                &format!("cx{}", i),
                &format!("l{}", i - 1),
                &format!("r{}", i + 1),
            );
        }

        // set x=i variables
        cs.muli(
            &format!("{name}={}", set[i]),
            &format!("cx{i}"),
            ONE / C(set[i]),
        );
    }

    cs.seal();
}

// Generate a circut which defines a set of selectors
// for an integer k, 0 <= k < n.

pub fn selector(cs: &mut R1CS, name: &str, n: u32, k: u32) {
    assert!(n > 2);
    assert!(k < n);

    let set = Vec::from_iter(0..n);
    member(cs, name, k, &set);
}

pub fn load_array(cs: &mut R1CS, input: &str, output: &str, arr: &str, size: u32, rs: u32) {
    debug_assert!(rs < size);
    for i in 0..size {
        debug_assert!(cs.has_var(&format!("{arr}{i}")));
    }

    selector(cs, input, size, rs);

    // construct witness
    // starting with selector
    let j = cs.new_var(input);
    cs.w[j] = F::from(rs);

    // register
    for i in 0..size {
        let reg = *cs.get_var(&format!("{arr}{i}"));
        let j = cs.new_local_var(&format!("rsx{i}"));
        cs.w[j] = if i == rs { reg } else { ZERO };
    }

    // output
    let j = cs.new_var(output);
    cs.w[j] = *cs.get_var(&format!("{arr}{rs}"));

    if cs.witness_only {
        cs.seal();
        return;
    }

    // build constraints
    // rsx_i = rs_i=i * x_i
    for i in 0..size {
        cs.mul(
            &format!("rsx{i}"),
            &format!("{input}={i}"),
            &format!("{arr}{i}"),
        );
    }

    // output = sum_i(rsx_i)
    cs.constraint(|cs, a, b, c| {
        for i in 0..size {
            let rj = cs.var(&format!("rsx{i}"));
            a[rj] = ONE;
        }
        b[0] = ONE;
        c[j] = ONE;
    });

    cs.seal();
}

pub fn load_reg(cs: &mut R1CS, input: &str, output: &str, rs: u32) {
    load_array(cs, input, output, "x", 32, rs)
}

pub fn store_reg(cs: &mut R1CS, input: &str, output: &str, rs: u32) {
    debug_assert!(rs < 32);
    for i in 0..32 {
        debug_assert!(cs.has_var(&format!("x{i}")));
    }
    debug_assert!(cs.has_var(output));

    let z = *cs.get_var(output);

    selector(cs, input, 32, rs);

    // construct witness
    // starting with selector
    let j = cs.new_var(input);
    cs.w[j] = F::from(rs);

    cs.new_var("x'0");
    cs.new_local_var("rsx0");
    cs.new_local_var("z0");

    for i in 1..32 {
        // output registers
        let reg = *cs.get_var(&format!("x{i}"));
        let j = cs.new_var(&format!("x'{i}"));
        cs.w[j] = if i == rs { z } else { reg };

        let j = cs.new_local_var(&format!("rsx{i}"));
        cs.w[j] = if i != rs { reg } else { ZERO };

        let j = cs.new_local_var(&format!("z{i}"));
        cs.w[j] = if i == rs { z } else { ZERO };
    }

    if cs.witness_only {
        cs.seal();
        return;
    }

    // build constraints
    for i in 1..32 {
        // rsx_i = (1 - rs_i=i) * x'_i
        let j1 = cs.var(&format!("{input}={i}"));
        let j2 = cs.var(&format!("x'{i}"));
        let j3 = cs.var(&format!("rsx{i}"));
        cs.constraint(|_cs, a, b, c| {
            a[0] = ONE;
            a[j1] = MINUS;
            b[j2] = ONE;
            c[j3] = ONE;
        });

        // z_i = rs_i=1 * z
        cs.mul(&format!("z{i}"), &format!("{input}={i}"), output);

        // x'_i = rsx_i + z_i
        cs.add(&format!("x'{i}"), &format!("rsx{i}"), &format!("z{i}"));
    }

    cs.seal();
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_bits(x: u32) {
        let mut cs = R1CS::default();
        cs.set_var("x", x);
        cs.to_bits("x", x);
        assert!(cs.is_sat());
        for i in 0..32 {
            let b = F::from((x >> i) & 1);
            assert!(cs.get_var(&format!("x_{i}")) == &b);
        }
    }

    #[test]
    fn test_to_bits() {
        let mut cs = R1CS::default();
        let j = cs.set_bit("b0", false);
        assert!(cs.is_sat());
        cs.w[j] = ONE;
        assert!(cs.is_sat());
        cs.w[j] = TWO;
        assert!(!cs.is_sat());

        for x in [0u32, 1, 0xcccccccc, 0x55555555, 0xabcdef98] {
            test_bits(x);
        }
    }

    #[test]
    fn test_from_bits() {
        let mut cs = R1CS::default();
        let x = cs.to_bits("x", 0xcccccccc);
        let y = cs.from_bits("y", 0xcccccccc, "x", 0, 32);
        assert!(cs.is_sat());
        assert_eq!(cs.w[x], cs.w[y]);

        let mut cs = R1CS::default();
        let _ = cs.to_bits("x", 0xcccccccc);
        let _ = cs.from_bits("y", 0xcccccccc, "x", 0, 32);
        let z = cs.from_bits("z", 0xcc, "x", 8, 16);
        assert!(cs.is_sat());
        assert_eq!(cs.w[z], F::from(0xcc));

        let mut cs = R1CS::default();
        let _ = cs.to_bits("x", 0xcccccccc);
        let _ = cs.from_bits("y", 0xcccccccc, "x", 0, 32);
        let z = cs.from_bits("z", 0x33, "x", 2, 8);
        assert!(cs.is_sat());
        assert_eq!(cs.w[z], F::from(0x33));
    }

    fn test_mem(set: &[u32]) {
        for &x in set {
            let mut cs = R1CS::default();
            member(&mut cs, "x", x, set);
            assert!(cs.is_sat());
            for &y in set {
                let v = cs.get_var(&format!("x={y}"));
                if x == y {
                    assert_eq!(v, &ONE);
                } else {
                    assert_eq!(v, &ZERO);
                }
            }
        }
    }

    #[test]
    fn test_member() {
        test_mem(&[2, 3]);
        test_mem(&[4, 7, 11, 19]);
        test_mem(&[57, 67, 77, 107, 117, 119]);
    }

    fn test_sel(n: u32) {
        for k in 0..n {
            let mut cs = R1CS::default();
            selector(&mut cs, "y", n, k);
            assert!(cs.is_sat());

            for i in 0..n {
                let v = cs.get_var(&format!("y={i}"));
                if i == k {
                    assert_eq!(v, &ONE);
                } else {
                    assert_eq!(v, &ZERO);
                }
            }
        }
    }

    #[test]
    fn test_selector() {
        test_sel(3);
        test_sel(4);
        test_sel(5);
        test_sel(32);
    }

    fn init_regs() -> R1CS {
        let mut cs = R1CS::default();
        for i in 0..32 {
            cs.set_var(&format!("x{i}"), i);
            cs.set_var(&format!("x'{i}"), i);
        }
        cs
    }

    #[test]
    fn test_load_reg() {
        for i in 0..32 {
            let mut cs = init_regs();
            load_reg(&mut cs, "rs1", "X", i);
            assert!(cs.is_sat());
            assert!(cs.w[cs.var("X")] == F::from(i));
        }
    }

    #[test]
    fn test_store_reg() {
        for i in 0..32 {
            let mut cs = init_regs();
            let j = cs.new_var("Z");
            let z = F::from(100);
            cs.w[j] = z;

            store_reg(&mut cs, "rd", "Z", i);
            assert!(cs.is_sat());

            for r in 0..32 {
                let j = cs.var(&format!("x'{r}"));
                if r == 0 {
                    assert!(cs.w[j] == ZERO);
                } else if r == i {
                    assert!(cs.w[j] == z);
                } else {
                    assert!(cs.w[j] == F::from(r));
                }
            }
        }
    }
}
