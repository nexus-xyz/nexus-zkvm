//! Circuits for the RISC-V VM (nexus-riscv)

use ark_ff::{BigInt, PrimeField};

use crate::instructions::{Opcode::*, *};
use crate::memory::MemoryProof;
use crate::trace::Witness;

use super::r1cs::*;

#[inline]
fn add32(x: u32, y: u32) -> u32 {
    x.overflowing_add(y).0
}

/// The arity of the NexusVM step circuit
pub const ARITY: usize = 34;

// Note: step circuit generation code depends on this ordering

fn init_cs(w: &Witness<impl MemoryProof>) -> R1CS {
    let mut cs = R1CS::default();
    cs.arity = ARITY;

    // inputs
    cs.set_var("pc", w.pc);
    for i in 0..32 {
        cs.set_var(&format!("x{i}"), w.regs[i]);
    }
    cs.set_field_var("root", w.pc_proof.commit());

    // outputs
    cs.set_var("PC", w.PC);
    for i in 0..32 {
        cs.set_var(&format!("x'{i}"), w.regs[i]);
    }
    cs.set_field_var("ROOT", w.write_proof.commit());

    // memory contents
    add_proof(&mut cs, "pc_mem", &w.pc_proof);
    add_proof(&mut cs, "read_mem", &w.read_proof);
    add_proof(&mut cs, "write_mem", &w.write_proof);
    cs
}

fn add_proof(cs: &mut R1CS, prefix: &str, proof: &impl MemoryProof) {
    let leaf = proof.data();
    cs.set_field_var(&format!("{}_lo", prefix), leaf[0]);
    cs.set_field_var(&format!("{}_hi", prefix), leaf[1]);
}

fn select_XY(cs: &mut R1CS, rs1: u8, rs2: u8) {
    load_reg(cs, "rs1", "X", rs1 as u32);
    load_reg(cs, "rs2", "Y", rs2 as u32);
}

fn select_Z(cs: &mut R1CS, rd: u32) {
    cs.new_var("Z");
    store_reg(cs, "rd", "Z", rd);
}

fn parse_inst(cs: &mut R1CS, inst: Inst) {
    let dword: u64 = inst.into();
    let word = (dword & 0xffffffff) as u32;

    cs.to_bits("inst", word);
    cs.from_bits("opcode", inst.opcode as u32, "inst", 0, 8);
    cs.from_bits("rd", inst.rd as u32, "inst", 17, 22);
    cs.from_bits("rs1", inst.rs1 as u32, "inst", 22, 27);
    cs.from_bits("rs2", inst.rs2 as u32, "inst", 27, 32);
}

/// Generate circuit for a single step of the NexusVM.
/// This circuit corresponds to `eval::step`.
pub fn step(vm: &Witness<impl MemoryProof>, witness_only: bool) -> R1CS {
    let mut cs = init_cs(vm);
    cs.witness_only = witness_only;

    select_XY(&mut cs, vm.inst.rs1, vm.inst.rs2);

    // check that inputs are 32-bit numbers
    cs.to_bits("pc", vm.pc);
    cs.to_bits("X", vm.X);
    cs.to_bits("Y", vm.Y);
    cs.to_bits("I", vm.inst.imm);
    cs.to_bits("Z", vm.Z);
    cs.to_bits("PC", vm.PC);

    add_cir(&mut cs, "X+I", "X", "I", vm.X, vm.inst.imm);
    add_cir(&mut cs, "Y+I", "Y", "I", vm.Y, vm.inst.imm);

    let YI = add32(vm.Y, vm.inst.imm);
    let shamt = YI & 0x1f;
    cs.to_bits("Y+I", YI);
    cs.from_bits("shamt", shamt, "Y+I", 0, 5);

    // possible values for PC
    cs.set_var("eight", 8);
    add_cir(&mut cs, "pc+8", "pc", "eight", vm.pc, 8);
    add_cir(&mut cs, "pc+I", "pc", "I", vm.pc, vm.inst.imm);

    load_inst(&mut cs, vm);
    parse_inst(&mut cs, vm.inst);

    // process alu first so we get definitions for common values
    alu(&mut cs, vm);
    br(&mut cs, vm);
    load(&mut cs, vm);
    store(&mut cs, vm);
    sys(&mut cs, vm);
    misc(&mut cs);

    #[rustfmt::skip]
    let opcodes = [
        NOP, HALT, SYS,
        JAL, BEQ, BNE, BLT, BGE, BLTU, BGEU,
        LB, LH, LW, LBU, LHU, SB, SH, SW,
        ADD, SUB, SLT, SLTU, SLL, SRL, SRA, OR, AND, XOR,
    ];
    let values = opcodes.iter().map(|x| *x as u32).collect::<Vec<_>>();

    member(&mut cs, "J", vm.inst.opcode as u32, &values);

    // constrain Z and PC according to opcode
    for opc in opcodes {
        let j = opc as u8;
        let current = opc == vm.inst.opcode;

        cs.set_var(&format!("JZ{j}"), if current { vm.Z } else { 0 });
        cs.mul(&format!("JZ{j}"), &format!("J={j}"), &format!("Z{j}"));

        cs.set_var(&format!("JPC{j}"), if current { vm.PC } else { 0 });
        cs.mul(&format!("JPC{j}"), &format!("J={j}"), &format!("PC{j}"));
    }

    // Z = Z[J]
    cs.constraint(|cs, a, b, c| {
        for opc in opcodes {
            let j = opc as u8;
            a[cs.var(&format!("JZ{j}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("Z")] = ONE;
    });

    // PC = PC[J]
    cs.constraint(|cs, a, b, c| {
        for opc in opcodes {
            let j = opc as u8;
            a[cs.var(&format!("JPC{j}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("PC")] = ONE;
    });

    // x[rd] = Z
    select_Z(&mut cs, vm.inst.rd as u32);
    cs
}

// We have several different addition circuits, all are built
// with this function

fn add_cir(cs: &mut R1CS, z_name: &str, x_name: &str, y_name: &str, x: u32, y: u32) {
    let O = F::from(0x100000000u64);
    let ON = ZERO - O;

    let (z, of) = x.overflowing_add(y);
    let o = if of { ON } else { ZERO };

    // construct witness
    let xj = cs.var(x_name);
    let yj = cs.var(y_name);
    let zj = cs.set_var(z_name, z);
    let oj = cs.new_local_var("O");
    cs.w[oj] = o;

    if cs.witness_only {
        cs.seal();
        return;
    }

    // constraints
    // check o * (o + O) == 0
    cs.constraint(|_cs, a, b, _c| {
        a[0] = O;
        a[oj] = ONE;
        b[oj] = ONE;
    });

    // x + y + o = z
    cs.constraint(|_cs, a, b, c| {
        a[xj] = ONE;
        a[yj] = ONE;
        a[oj] = ONE;
        b[0] = ONE;
        c[zj] = ONE;
    });

    cs.seal();
}

fn alu(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    add(cs, vm);
    sub(cs, vm);
    slt(cs);
    shift(cs, vm);
    bitops(cs, vm);

    let start = ADD as u8;
    let end = XOR as u8;
    for j in start..end + 1 {
        cs.set_eq(&format!("PC{j}"), "pc+8");
    }
}

fn add(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    const J: u8 = ADD as u8;

    add_cir(cs, "X+Y+I", "X", "Y+I", vm.X, add32(vm.Y, vm.inst.imm));
    cs.set_eq(&format!("Z{J}"), "X+Y+I");
}

// this is similar to add_cir, but we also compute the condition flags

fn sub_cir(cs: &mut R1CS, z_name: &str, x_name: &str, y_name: &str, x: u32, y: u32) {
    let O = F::from(0x100000000u64);

    let (z, of) = x.overflowing_sub(y);

    // construct witness
    let xj = cs.var(x_name);
    let yj = cs.var(y_name);
    let oj = cs.set_bit(&format!("{x_name}<{y_name}"), of);
    let zj = cs.set_var(z_name, z);

    // constraints
    // x - y + O*o = z
    cs.constraint(|_cs, a, b, c| {
        a[xj] = ONE;
        a[yj] = MINUS;
        a[oj] = O;
        b[0] = ONE;
        c[zj] = ONE;
    });

    // set condition flags
    // LT flag is the unsigned overflow (already set above)
    let lt = x < y;
    let ltj = oj;

    // EQ flag (a.k.a ZERO flag)
    let eqj = cs.set_bit(&format!("{x_name}={y_name}"), x == y);

    // X=Y * Z = 0
    cs.constraint(|_cs, a, b, _c| {
        a[zj] = ONE;
        b[eqj] = ONE;
    });

    // GE flag
    let ge = x >= y;
    let gej = cs.set_bit(&format!("{x_name}>={y_name}"), ge);

    // X<Y + X>=Y = 1
    cs.constraint(|_cs, a, b, c| {
        a[ltj] = ONE;
        a[gej] = ONE;
        b[0] = ONE;
        c[0] = ONE;
    });

    // NE flag
    let nej = cs.set_bit(&format!("{x_name}!={y_name}"), x != y);

    // X=Y + X!=Y = 1
    cs.constraint(|_cs, a, b, c| {
        a[eqj] = ONE;
        a[nej] = ONE;
        b[0] = ONE;
        c[0] = ONE;
    });

    // signed lt and gte
    let sltj = cs.set_bit(&format!("{x_name}<s{y_name}"), (x as i32) < (y as i32));
    let sgej = cs.set_bit(&format!("{x_name}>=s{y_name}"), (x as i32) >= (y as i32));

    // sgt = !slt
    cs.constraint(|_cs, a, b, c| {
        a[0] = ONE;
        a[sltj] = MINUS;
        b[0] = ONE;
        c[sgej] = ONE;
    });

    // invert < if X and Y differ in sign
    // different signs (ds)
    let xs = x >> 31;
    let ys = y >> 31;
    let ds = (xs ^ ys) != 0;
    let dsj = cs.new_local_var("ds");
    cs.set_bit("ds", ds);

    // compute XOR of X and Y sign bits
    let j = cs.new_local_var("Xs*Ys");
    cs.w[j] = F::from(xs * ys);
    cs.mul("Xs*Ys", &format!("{x_name}_31"), &format!("{y_name}_31"));

    // X_31 + Y_31 - 2 X_31 Y_31 = ds  (XOR)
    cs.constraint(|cs, a, b, c| {
        a[cs.var(&format!("{x_name}_31"))] = ONE;
        a[cs.var(&format!("{y_name}_31"))] = ONE;
        a[j] = F::from(-2);
        b[0] = ONE;
        c[dsj] = ONE;
    });

    // slt = ds (1 - lt) + (1 - ds) lt
    let left = cs.new_local_var("sltl");
    cs.set_bit("sltl", ds & !lt);
    cs.constraint(|_cs, a, b, c| {
        a[dsj] = ONE;
        b[0] = ONE;
        b[ltj] = MINUS;
        c[left] = ONE;
    });

    let right = cs.new_local_var("sltr");
    cs.set_bit("sltr", !ds & lt);
    cs.constraint(|_cs, a, b, c| {
        a[0] = ONE;
        a[dsj] = MINUS;
        b[ltj] = ONE;
        c[right] = ONE;
    });

    // slt = left + right
    cs.constraint(|_cs, a, b, c| {
        a[left] = ONE;
        a[right] = ONE;
        b[0] = ONE;
        c[sltj] = ONE;
    });

    cs.seal();
}

fn sub(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    const J: u8 = SUB as u8;

    sub_cir(cs, "X-Y+I", "X", "Y+I", vm.X, add32(vm.Y, vm.inst.imm));
    cs.set_eq(&format!("Z{J}"), "X-Y+I");
}

fn slt(cs: &mut R1CS) {
    let J = SLT as u8;
    cs.set_eq(&format!("Z{J}"), "X<sY+I");

    let J = SLTU as u8;
    cs.set_eq(&format!("Z{J}"), "X<Y+I");
}

fn branch(cs: &mut R1CS, J: u8, cond_name: &str, inverse_cond_name: &str) {
    let output = &format!("PC{J}");
    let cond_val = cs.get_var(cond_name);
    let cond = if *cond_val == ZERO {
        false
    } else if *cond_val == ONE {
        true
    } else {
        panic!("{cond_name} is not a boolean value")
    };

    let pc_imm = *cs.get_var("pc+I");
    let pc_next = *cs.get_var("pc+8");
    let PC = if cond { pc_imm } else { pc_next };

    // PC = cond (pc + I) + !cond (pc + 8)
    let left = cs.new_local_var("left");
    cs.w[left] = if cond { pc_imm } else { ZERO };
    cs.mul("left", cond_name, "pc+I");

    let right = cs.new_local_var("right");
    cs.w[right] = if !cond { pc_next } else { ZERO };
    cs.mul("right", inverse_cond_name, "pc+8");

    let j = cs.new_var(output);
    cs.w[j] = PC;
    cs.add(output, "left", "right");

    // output
    let j = cs.set_var(&format!("Z{J}"), 0);
    cs.constraint(|_cs, a, b, _c| {
        a[j] = ONE;
        b[0] = ONE;
    });
    cs.seal();
}

fn br(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let J = JAL as u8;
    cs.set_eq(&format!("Z{J}"), "pc+8");
    // call/ret is slightly different from jalr (see:eval.rs)
    let j = cs.new_var(&format!("PC{J}"));
    if vm.inst.rs1 > 1 {
        cs.w[j] = *cs.get_var("X+I") * TWO;
    } else {
        cs.w[j] = *cs.get_var("X+I");
    }
    cs.constraint(|cs, a, b, c| {
        a[0] = ONE;
        for i in 2..32 {
            a[cs.var(&format!("rs1={i}"))] = ONE;
        }
        b[cs.var("X+I")] = ONE;
        c[j] = ONE;
    });

    sub_cir(cs, "X-Y", "X", "Y", vm.X, vm.Y);

    let J = BEQ as u8;
    branch(cs, J, "X=Y", "X!=Y");

    let J = BNE as u8;
    branch(cs, J, "X!=Y", "X=Y");

    let J = BLT as u8;
    branch(cs, J, "X<sY", "X>=sY");

    let J = BGE as u8;
    branch(cs, J, "X>=sY", "X<sY");

    let J = BLTU as u8;
    branch(cs, J, "X<Y", "X>=Y");

    let J = BGEU as u8;
    branch(cs, J, "X>=Y", "X<Y");
}

fn choose(cs: &mut R1CS, result: &str, bit: &str, left: &str, right: &str) {
    let result = cs.new_var(result);
    let bit = cs.var(bit);
    let left = cs.var(left);
    let right = cs.var(right);

    let li = cs.new_local_var(&format!("{result}_left"));
    let ri = cs.new_local_var(&format!("{result}_right"));

    if cs.w[bit] == ONE {
        cs.w[result] = cs.w[left];
        cs.w[li] = cs.w[left];
        cs.w[ri] = ZERO;
    } else {
        cs.w[result] = cs.w[right];
        cs.w[li] = ZERO;
        cs.w[ri] = cs.w[right];
    };

    if cs.witness_only {
        return;
    }

    // li = bit * left
    cs.constraint(|_cs, a, b, c| {
        a[bit] = ONE;
        b[left] = ONE;
        c[li] = ONE;
    });

    // ri = (1 - bit) * right
    cs.constraint(|_cs, a, b, c| {
        a[0] = ONE;
        a[bit] = MINUS;
        b[right] = ONE;
        c[ri] = ONE;
    });

    // result = bit * left + bit * right
    cs.constraint(|_cs, a, b, c| {
        a[li] = ONE;
        a[ri] = ONE;
        b[0] = ONE;
        c[result] = ONE;
    });
}

fn split128(cs: &mut R1CS, scalar: &str, widths: &[usize]) {
    let BigInt([a, b, _, _]) = cs.get_var(scalar).into_bigint();
    let val = (b as u128) << 64 | (a as u128);

    let mut v = val;
    for i in 0..128 {
        cs.set_bit(&format!("{scalar}_{i}"), (v & 1) != 0);
        v >>= 1;
    }

    for bits in widths {
        let mask = (1u128 << bits) - 1;
        v = val;
        for i in 0..(128 / bits) {
            let x = (v & mask) as u32;
            v >>= bits;
            let ndx = cs.set_var(&format!("{scalar}_{bits}_{i}"), x);
            cs.constraint(|cs, a, b, c| {
                let mut pow = ONE;
                for j in (i * bits)..(i * bits + bits) {
                    a[cs.var(&format!("{scalar}_{j}"))] = pow;
                    pow *= TWO;
                }
                b[0] = ONE;
                c[ndx] = ONE;
            });
        }
    }
}

fn load_select(cs: &mut R1CS, addr_name: &str, name: &str, addr: u32, word_only: bool) {
    choose(
        cs,
        name,
        &format!("{addr_name}_4"),
        &format!("{name}_hi"),
        &format!("{name}_lo"),
    );

    let widths: &[usize] = if word_only { &[32] } else { &[8, 16, 32] };

    split128(cs, name, widths);

    let mut addr = addr & 0xf;
    let mut count = 16;
    if widths.len() == 1 {
        addr >>= 2;
        count >>= 2;
    }
    for width in widths {
        load_array(
            cs,
            &format!("{addr_name}{width}"),
            &format!("{name}{width}"),
            &format!("{name}_{width}_"),
            count,
            addr,
        );
        addr >>= 1;
        count >>= 1;
    }
}

fn load_inst(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    load_select(cs, "pc", "pc_mem", vm.pc, true);

    cs.equal_scalar("pc_0", ZERO);
    cs.equal_scalar("pc_1", ZERO);
    cs.equal_scalar("pc_2", ZERO);
    cs.set_not("not_pc_3", "pc_3");

    cs.new_local_var("lo");
    cs.new_local_var("hi");
    cs.set_mul("lo", "not_pc_3", "pc_mem_32_1");
    cs.set_mul("hi", "pc_3", "pc_mem_32_3");
    cs.set_add("I", "hi", "lo");
    cs.set_eq("inst", "pc_mem32");

    cs.seal();
}

fn sx8(cs: &mut R1CS, output: &str, input: &str) {
    let input_i = cs.var(input);
    let BigInt([a, _, _, _]) = cs.w[input_i].into_bigint();

    let sb = (a & 0x80) != 0;
    let sv = (a & 0x7f) as u32;
    let sx = if sb { 0xffffff80 | sv } else { sv };

    let sb_i = cs.set_bit(&format!("{input}_sb"), sb);
    let sv_i = cs.set_var(&format!("{input}_sv"), sv);
    let sx_i = cs.set_var(output, sx);

    if cs.witness_only {
        return;
    }

    // input = sv + sb * 0x80
    cs.constraint(|_cs, a, b, c| {
        a[sv_i] = ONE;
        a[sb_i] = F::from(0x80);
        b[0] = ONE;
        c[input_i] = ONE;
    });
    // output = sv + sb * 0xffffff80
    cs.constraint(|_cs, a, b, c| {
        a[sv_i] = ONE;
        a[sb_i] = F::from(0xffffff80u32);
        b[0] = ONE;
        c[sx_i] = ONE;
    });
}

fn sx16(cs: &mut R1CS, output: &str, input: &str) {
    let input_i = cs.var(input);
    let BigInt([a, _, _, _]) = cs.w[input_i].into_bigint();

    let sb = (a & 0x8000) != 0;
    let sv = (a & 0x7fff) as u32;
    let sx = if sb { 0xffff8000 | sv } else { sv };

    let sb_i = cs.set_bit(&format!("{input}_sb"), sb);
    let sv_i = cs.set_var(&format!("{input}_sv"), sv);
    let sx_i = cs.set_var(output, sx);

    if cs.witness_only {
        return;
    }

    // input = sv + sb * 0x80
    cs.constraint(|_cs, a, b, c| {
        a[sv_i] = ONE;
        a[sb_i] = F::from(0x8000);
        b[0] = ONE;
        c[input_i] = ONE;
    });
    // output = sv + sb * 0xffffff80
    cs.constraint(|_cs, a, b, c| {
        a[sv_i] = ONE;
        a[sb_i] = F::from(0xffff8000u32);
        b[0] = ONE;
        c[sx_i] = ONE;
    });
}

fn load(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let addr = vm.X.overflowing_add(vm.inst.imm).0;
    cs.to_bits("X+I", addr);
    load_select(cs, "X+I", "read_mem", addr, false);

    let J = LW as u8;
    cs.set_eq(&format!("Z{J}"), "read_mem32");
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = LHU as u8;
    cs.set_eq(&format!("Z{J}"), "read_mem16");
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = LBU as u8;
    cs.set_eq(&format!("Z{J}"), "read_mem8");
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = LB as u8;
    sx8(cs, &format!("Z{J}"), "read_mem8");
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = LH as u8;
    sx16(cs, &format!("Z{J}"), "read_mem16");
    cs.set_eq(&format!("PC{J}"), "pc+8");
}

fn store(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let addr = vm.X.overflowing_add(vm.inst.imm).0;
    load_select(cs, "X+I", "write_mem", addr, false);

    let J = SW as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = SH as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = SB as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc+8");
}

// shift operations
//
// There are two basic approaches to shift, the most obvious is
// to define each output bit as a sum of products of input bits
// with selector variables, e.g.:
//   Z_0 = SUM shamt=_i x_i
//   Z_1 = SUM shamt_i x_{i+1}
// Then, we have
//   Z = SUM Z_i
// this produces a lot of witness variables
//
// The other approach, taken here, is to define 32 complete
// outputs and then select the correct one, e.g.
//   Z0 = SUM 2^i x_i
//   Z1 = SUM 2^i x_{i+1}
// Then, we have
//   Z = SUM Zi shamt=i
// this produces fewer witness variables, but denser
// constraints

fn shift_right(cs: &mut R1CS, output: &str, X: u32, I: u32, arith: bool) {
    if arith {
        cs.set_var(output, ((X as i32) >> I) as u32);
    } else {
        cs.set_var(output, X >> I);
    }

    for amt in 0..32 {
        let out = if arith {
            ((X as i32) >> amt) as u32
        } else {
            X >> amt
        };

        // generate potential outputs
        if amt == 0 {
            cs.new_local_var("out0");
            cs.set_eq("out0", "X");
        } else {
            let j = cs.new_local_var(&format!("out{amt}"));
            cs.w[j] = F::from(out);
            cs.constraint(|cs, a, b, c| {
                for bit in 0..32 {
                    if bit + amt < 32 {
                        a[cs.var(&format!("X_{}", bit + amt))] = F::from(1u64 << bit);
                    } else if arith {
                        let k = cs.var("X_31");
                        a[k] += F::from(1u64 << bit);
                    }
                }
                b[0] = ONE;
                c[j] = ONE;
            });
        }

        // generate final output products
        let j = cs.new_local_var(&format!("SZ{amt}"));
        cs.w[j] = if amt == I { F::from(out) } else { ZERO };
        cs.mul(
            &format!("SZ{amt}"),
            &format!("shamt={amt}"),
            &format!("out{amt}"),
        );
    }

    // generate final output
    cs.constraint(|cs, a, b, c| {
        for amt in 0..32 {
            let k = cs.var(&format!("SZ{amt}"));
            a[k] = ONE;
        }
        b[0] = ONE;
        c[cs.var(output)] = ONE;
    });

    cs.seal();
}

fn shift_left(cs: &mut R1CS, output: &str, X: u32, I: u32) {
    cs.set_var(output, X << I);

    for amt in 0..32 {
        let out = X << amt;

        // generate potential outputs
        if amt == 0 {
            cs.new_local_var("out0");
            cs.set_eq("out0", "X");
        } else {
            let j = cs.new_local_var(&format!("out{amt}"));
            cs.w[j] = F::from(out);
            cs.constraint(|cs, a, b, c| {
                for bit in 0..32 {
                    if bit >= amt {
                        a[cs.var(&format!("X_{}", bit - amt))] = F::from(1u64 << bit);
                    }
                }
                b[0] = ONE;
                c[j] = ONE;
            });
        }

        // generate final output products
        let j = cs.new_local_var(&format!("SZ{amt}"));
        cs.w[j] = if amt == I { F::from(out) } else { ZERO };
        cs.mul(
            &format!("SZ{amt}"),
            &format!("shamt={amt}"),
            &format!("out{amt}"),
        );
    }

    // generate final output
    cs.constraint(|cs, a, b, c| {
        for amt in 0..32 {
            let k = cs.var(&format!("SZ{amt}"));
            a[k] = ONE;
        }
        b[0] = ONE;
        c[cs.var(output)] = ONE;
    });

    cs.seal();
}

fn shift(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let shamt = add32(vm.Y, vm.inst.imm) & 0x1f;
    selector(cs, "shamt", 32, shamt);

    let J = SLL as u8;
    shift_left(cs, &format!("Z{J}"), vm.X, shamt);

    let J = SRL as u8;
    shift_right(cs, &format!("Z{J}"), vm.X, shamt, false);

    let J = SRA as u8;
    shift_right(cs, &format!("Z{J}"), vm.X, shamt, true);
}

fn bit(x: u32, bit: u32) -> bool {
    ((x >> bit) & 1) != 0
}

fn bitop(cs: &mut R1CS, output: &str, y_name: &str, z: u32, adj: F) {
    cs.to_bits(output, z);
    for i in 0..32 {
        let j = cs.set_bit(&format!("{output}_{i}"), bit(z, i));
        cs.constraint(|cs, a, b, c| {
            a[cs.var(&format!("X_{i}"))] = ONE;
            a[cs.var(&format!("{y_name}_{i}"))] = ONE;
            a[cs.var(&format!("X&{y_name}_{i}"))] = adj;
            b[0] = ONE;
            c[j] = ONE;
        });
    }
}

fn bitops(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let YI = add32(vm.Y, vm.inst.imm);

    // and
    let XY = vm.X & YI;
    cs.to_bits("X&Y+I", XY);
    for i in 0..32 {
        cs.set_bit(&format!("X&Y+I_{i}"), bit(XY, i));
        cs.mul(
            &format!("X&Y+I_{i}"),
            &format!("X_{i}"),
            &format!("Y+I_{i}"),
        );
    }

    let J = AND as u8;
    cs.set_eq(&format!("Z{J}"), "X&Y+I");

    // or
    let J = OR as u8;
    bitop(cs, &format!("Z{J}"), "Y+I", vm.X | YI, MINUS);

    // xor
    let J = XOR as u8;
    bitop(cs, &format!("Z{J}"), "Y+I", vm.X ^ YI, F::from(-2));
}

fn sys(cs: &mut R1CS, vm: &Witness<impl MemoryProof>) {
    let J = SYS as u8;
    cs.set_var(&format!("Z{J}"), vm.Z);
    cs.set_eq(&format!("PC{J}"), "pc+8");
}

fn misc(cs: &mut R1CS) {
    let J = NOP as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc+8");

    let J = HALT as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc");

    let J = SYS as u8;
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc+8");
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::memory::cacheline::CacheLine;
    use crate::memory::path::Path;
    use num_traits::FromPrimitive;

    type Witness = crate::trace::Witness<Path>;

    #[test]
    fn test_load_inst() {
        let values = [0, 1, 8, 9, 16, 17, 24, 25];
        let cl = CacheLine::from(values);
        let mut vm = Witness::default();
        vm.pc_proof.leaf = cl.scalars();

        for addr in [0, 8, 16, 24] {
            vm.pc = addr;
            let mut cs = R1CS::default();
            add_proof(&mut cs, "pc_mem", &vm.pc_proof);
            cs.to_bits("pc", vm.pc);
            load_inst(&mut cs, &vm);
            assert!(cs.is_sat());
            assert_eq!(cs.get_var("inst"), &F::from(addr));
            assert_eq!(cs.get_var("I"), &F::from(addr + 1));
        }
    }

    #[test]
    fn test_parse_inst() {
        // note the immediate is handled by load_inst
        for opc in 0..0x50 {
            let Some(opcode) = Opcode::from_u8(opc) else {
                continue;
            };
            for rd in [0, 1, 31] {
                for rs1 in [0, 1, 31] {
                    for rs2 in [0, 1, 31] {
                        let inst = Inst { opcode, rd, rs1, rs2, imm: 0 };
                        let mut cs = R1CS::default();
                        parse_inst(&mut cs, inst);
                        assert!(cs.is_sat());
                        assert_eq!(cs.get_var("opcode"), &F::from(opc as u64));
                        assert_eq!(cs.get_var("rd"), &F::from(rd as u64));
                        assert_eq!(cs.get_var("rs1"), &F::from(rs1 as u64));
                        assert_eq!(cs.get_var("rs2"), &F::from(rs2 as u64));
                    }
                }
            }
        }
    }

    #[test]
    fn test_select_XY() {
        let regs: [u32; 32] = core::array::from_fn(|i| i as u32);
        let w = Witness { regs, ..Witness::default() };
        for x in [0, 1, 2, 31] {
            for y in [0, 6, 13] {
                let mut cs = init_cs(&w);
                select_XY(&mut cs, x, y);
                assert!(cs.is_sat());
                assert!(cs.get_var("X") == &F::from(x));
                assert!(cs.get_var("Y") == &F::from(y));
            }
        }
    }

    #[test]
    fn test_select_Z() {
        let regs: [u32; 32] = core::array::from_fn(|i| i as u32);
        let w = Witness { regs, ..Witness::default() };
        for i in 0..32 {
            let mut cs = init_cs(&w);
            let j = cs.new_var("Z");
            let z = F::from(100);
            cs.w[j] = z;

            select_Z(&mut cs, i);
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

    #[test]
    fn test_add() {
        let mut vm = Witness::default();
        for x in [0, 1, 0xffffffff] {
            for y in [0, 1, 100] {
                vm.X = x;
                vm.Y = y;
                let mut cs = R1CS::default();
                cs.set_var("X", x);
                cs.set_var("Y+I", y);
                add(&mut cs, &vm);
                assert!(cs.is_sat());
                assert!(cs.get_var("Z64") == &F::from(add32(x, y)));
            }
        }
    }

    #[test]
    fn test_sub() {
        let mut vm = Witness::default();
        for x in [0, 1, 0xfffffff0, 0xffffffff] {
            for y in [0, 1, 0xfffffff0, 0xffffffff] {
                vm.X = x;
                vm.Y = y;
                let mut cs = R1CS::default();
                cs.set_var("X", x);
                cs.set_var("Y", y);
                cs.set_var("Y+I", y);
                cs.to_bits("X", x);
                cs.to_bits("Y", y);
                cs.to_bits("Y+I", y);
                sub(&mut cs, &vm);

                assert!(cs.is_sat());
                assert!(cs.get_var("Z65") == &F::from(x.overflowing_sub(y).0));

                assert!(cs.get_var("X<Y+I") == &F::from(x < y));
                assert!(cs.get_var("X>=Y+I") == &F::from(x >= y));
                assert!(cs.get_var("X=Y+I") == &F::from(x == y));
                assert!(cs.get_var("X!=Y+I") == &F::from(x != y));

                assert!(cs.get_var("X<sY+I") == &F::from((x as i32) < (y as i32)));
                assert!(cs.get_var("X>=sY+I") == &F::from((x as i32) >= (y as i32)));
            }
        }
    }

    #[test]
    fn test_br() {
        let w = Witness { Y: 1, ..Witness::default() };
        let mut cs = R1CS::default();
        cs.set_var("rs1=0", 1);
        for i in 1..32 {
            cs.set_var(&format!("rs1={i}"), 0);
        }
        cs.set_var("pc+I", 1);
        cs.set_var("pc+8", 0);
        cs.to_bits("X", 0);
        cs.to_bits("Y", 1);
        cs.set_var("X+I", 0); // for JAL
        br(&mut cs, &w);
        assert!(cs.is_sat());
        assert_eq!(cs.get_var("PC17"), &ZERO);
        assert_eq!(cs.get_var("PC18"), &ONE);
        assert_eq!(cs.get_var("PC19"), &ONE);
        assert_eq!(cs.get_var("PC20"), &ZERO);
        assert_eq!(cs.get_var("PC21"), &ONE);
        assert_eq!(cs.get_var("PC22"), &ZERO);
    }

    #[test]
    fn test_shift() {
        let mut vm = Witness::default();
        for x in [0x7aaaaaaa, 0xf5555555] {
            for a in [0, 1, 10, 13, 30, 31] {
                vm.X = x;
                vm.Y = a;
                let mut cs = R1CS::default();
                cs.to_bits("X", x);

                shift(&mut cs, &vm);

                assert!(cs.is_sat());
                assert!(cs.get_var("Z68") == &F::from(x << a));
                assert!(cs.get_var("Z69") == &F::from(x >> a));
                assert!(cs.get_var("Z70") == &F::from(((x as i32) >> a) as u32));
            }
        }
    }

    #[test]
    fn test_bitops() {
        let mut vm = Witness::default();
        for x in [0u32, 0xaaaaaaaa, 0x55555555, 0xffffffff] {
            for y in [0u32, 0xaaaaaaaa, 0x55555555, 0xffffffff] {
                vm.X = x;
                vm.Y = y;
                let mut cs = R1CS::default();
                cs.to_bits("X", x);
                cs.to_bits("Y+I", y);

                bitops(&mut cs, &vm);

                assert!(cs.is_sat());

                assert!(cs.get_var("Z72") == &F::from(x & y));
                assert!(cs.get_var("Z71") == &F::from(x | y));
                assert!(cs.get_var("Z73") == &F::from(x ^ y));
            }
        }
    }

    #[test]
    fn test_memory_lw() {
        let values = [1, 2, 3, 4, 5, 6, 7, 8];
        let cl = CacheLine::from(values);
        let mut vm = Witness::default();
        vm.read_proof.leaf = cl.scalars();

        for (i, value) in values.iter().enumerate() {
            vm.X = (i * 4) as u32;
            let mut cs = init_cs(&vm);
            cs.to_bits("X", vm.X);
            load_select(&mut cs, "X", "read_mem", vm.X, false);

            assert!(cs.is_sat());
            assert_eq!(cs.get_var("read_mem32"), &F::from(*value));
            assert_eq!(cs.get_var("read_mem16"), &F::from(*value));
            assert_eq!(cs.get_var("read_mem8"), &F::from(*value));
        }
    }

    #[test]
    fn test_memory_lb() {
        let values: [u8; 32] = core::array::from_fn(|i| i as u8);
        let cl = CacheLine::from(values);
        let mut vm = Witness::default();
        vm.read_proof.leaf = cl.scalars();

        for i in values.iter() {
            vm.X = *i as u32;
            let mut cs = init_cs(&vm);
            cs.to_bits("X", vm.X);
            load_select(&mut cs, "X", "read_mem", vm.X, false);

            assert!(cs.is_sat());
            assert_eq!(cs.get_var("read_mem8"), &F::from(*i));
        }
    }

    #[test]
    fn test_memory_sx() {
        let values = [0, 0x01028384, 0, 0, 0, 0, 0, 0];
        let cl = CacheLine::from(values);
        let mut vm = Witness::default();
        vm.read_proof.leaf = cl.scalars();

        vm.X = 4;
        let mut cs = init_cs(&vm);
        cs.set_var("X+I", vm.X);
        cs.set_var("pc+8", 8);
        load(&mut cs, &vm);

        assert!(cs.is_sat());
        assert_eq!(cs.get_var("Z35"), &F::from(0x84));
        assert_eq!(cs.get_var("Z36"), &F::from(0x8384));
        assert_eq!(cs.get_var("Z32"), &F::from(0xffffff84u32));
        assert_eq!(cs.get_var("Z33"), &F::from(0xffff8384u32));
    }
}
