//! Circuits for the RISC-V VM (nexus-riscv)

use super::r1cs::*;

use nexus_riscv::vm::trace::*;
use nexus_riscv::rv32::{*, parse::*};

// Note: circuit generation code depends on this ordering
// (inputs: pc,x0..31 and then outputs: PC,x'0..31)

#[allow(clippy::field_reassign_with_default)]
#[allow(clippy::needless_range_loop)]
fn init_cs(pc: u32, regs: &[u32; 32]) -> R1CS {
    let mut cs = R1CS::default();
    cs.arity = 33;
    cs.set_var("pc", pc);
    for i in 0..32 {
        cs.set_var(&format!("x{i}"), regs[i]);
    }
    cs.set_var("PC", pc);
    for i in 0..32 {
        cs.set_var(&format!("x'{i}"), regs[i]);
    }
    cs
}

fn select_XY(cs: &mut R1CS, rs1: u32, rs2: u32) {
    load_reg(cs, "rs1", "X", rs1);
    load_reg(cs, "rs2", "Y", rs2);
}

fn select_Z(cs: &mut R1CS, rd: u32) {
    cs.new_var("Z");
    store_reg(cs, "rd", "Z", rd);
}

fn parse_opc(cs: &mut R1CS, inst: u32) {
    cs.to_bits("inst", inst);

    cs.set_bit("type=R", false);
    cs.set_bit("type=I", false);
    cs.set_bit("type=S", false);
    cs.set_bit("type=B", false);
    cs.set_bit("type=U", false);
    cs.set_bit("type=J", false);
    cs.set_bit("type=A", false);

    let opc = opcode(inst);
    #[rustfmt::skip]
    match opc {
        OPC_LUI   => cs.set_var("type=U", 1),
        OPC_AUIPC => cs.set_var("type=U", 1),
        OPC_JAL   => cs.set_var("type=J", 1),
        OPC_JALR  => cs.set_var("type=I", 1),
        OPC_BR    => cs.set_var("type=B", 1),
        OPC_LOAD  => cs.set_var("type=I", 1),
        OPC_STORE => cs.set_var("type=S", 1),
        OPC_ALUI  => cs.set_var("type=A", 1),
        OPC_ALU   => cs.set_var("type=R", 1),
        OPC_FENCE => cs.set_var("type=R", 1),
        OPC_ECALL => cs.set_var("type=R", 1),
        _ => panic!("invalid opcode {opc:x}")
    };

    #[rustfmt::skip]
    member(cs, "opcode", opc, &[
        OPC_LUI, OPC_AUIPC,
        OPC_JAL, OPC_JALR, OPC_BR,
        OPC_LOAD, OPC_STORE,
        OPC_ALUI, OPC_ALU,
        OPC_FENCE, OPC_ECALL
    ]);

    // constraints
    // type=J
    cs.set_eq("type=J", &format!("opcode={OPC_JAL}"));

    // type=B
    cs.set_eq("type=B", &format!("opcode={OPC_BR}"));

    // type=S
    cs.set_eq("type=S", &format!("opcode={OPC_STORE}"));

    // type=A
    cs.set_eq("type=A", &format!("opcode={OPC_ALUI}"));

    if cs.witness_only {
        cs.seal();
        return;
    }

    // type=I
    cs.add("type=I", &format!("opcode={OPC_JALR}"), &format!("opcode={OPC_LOAD}"));

    // type=U
    cs.add("type=U", &format!("opcode={OPC_LUI}"), &format!("opcode={OPC_AUIPC}"));

    // type=R
    cs.constraint(|cs, a, b, c| {
        for op in [OPC_ALU, OPC_FENCE, OPC_ECALL] {
            a[cs.var(&format!("opcode={op}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("type=R")] = ONE;
    });

    // parse inst
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 0..7 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        b[0] = ONE;
        c[cs.var("opcode")] = ONE;
    });

    // parse rd
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 7..12 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }

        b[0] = ONE;
        for op in [OPC_BR, OPC_STORE, OPC_ECALL] {
            b[cs.var(&format!("opcode={op}"))] = MINUS;
        }
        c[cs.var("rd")] = ONE;
    });

    // parse rs1
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 15..20 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }

        b[0] = ONE;
        for op in [OPC_LUI, OPC_AUIPC, OPC_JAL, OPC_ECALL] {
            b[cs.var(&format!("opcode={op}"))] = MINUS;
        }
        c[cs.var("rs1")] = ONE;
    });

    // parse rs2
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 20..25 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }

        for op in [OPC_BR, OPC_STORE, OPC_ALU] {
            b[cs.var(&format!("opcode={op}"))] = ONE;
        }
        c[cs.var("rs2")] = ONE;
    });

    cs.seal();
}

fn parse_imm(cs: &mut R1CS, inst: u32) {
    // add various immediates to witness
    cs.set_var("immI", immI(inst));
    cs.set_var("immS", immS(inst));
    cs.set_var("immB", immB(inst));
    cs.set_var("immU", immU(inst));
    cs.set_var("immJ", immJ(inst));
    cs.set_var("immA", immA(inst));
    cs.set_var("lowA", shamt(inst));

    // function 3
    selector(cs, "f3", 8, funct3(inst));

    // zero non-active immediates
    for ty in ["I", "S", "B", "U", "J", "A"] {
        let x = cs.get_var(&format!("type={ty}")) * cs.get_var(&format!("imm{ty}"));
        let j = cs.new_local_var(&format!("ti{ty}"));
        cs.w[j] = x;
    }

    // compute immA
    // is shift (for immA)
    let iss_j = cs.new_local_var("is_shift");
    cs.w[iss_j] = cs.get_var("f3=1") + cs.get_var("f3=5");

    let a1 = cs.new_local_var("a1");
    cs.w[a1] = cs.w[iss_j] * cs.get_var("lowA");

    let a2 = cs.new_local_var("a2");
    cs.w[a2] = (ONE - cs.w[iss_j]) * cs.get_var("immI");

    if cs.witness_only {
        cs.seal();
        return;
    }

    // constraints
    // immA
    cs.add("is_shift", "f3=1", "f3=5");
    cs.mul("a1", "is_shift", "lowA");
    cs.constraint(|cs, a, b, c| {
        a[0] = ONE;
        a[iss_j] = MINUS;
        b[cs.var("immI")] = ONE;
        c[a2] = ONE;
    });
    cs.add("immA", "a1", "a2");

    // I is one of the immediates
    cs.constraint(|cs, a, b, c| {
        for ty in ["I", "S", "B", "U", "J", "A"] {
            a[cs.var(&format!("ti{ty}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("I")] = ONE;
    });

    // parse lowA
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 20..25 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        b[0] = ONE;
        c[cs.var("lowA")] = ONE;
    });

    // function3
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 12..15 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        b[0] = ONE;
        c[cs.var("f3")] = ONE;
    });

    // sign bit
    let sb = cs.var("inst_31");

    // parse immI
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 20..31 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        a[sb] = F::from(0xfffff800u32);

        b[0] = ONE;
        c[cs.var("immI")] = ONE;
    });

    // parse immS
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 7..12 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        for i in 25..31 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        a[sb] = F::from(0xfffff800u32);

        b[0] = ONE;
        c[cs.var("immS")] = ONE;
    });

    // parse immB
    cs.constraint(|cs, a, b, c| {
        let mut pow = TWO;
        for i in 8..12 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        for i in 25..31 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        a[cs.var("inst_7")] = pow;

        a[sb] = F::from(0xfffff000u32);

        b[0] = ONE;
        c[cs.var("immB")] = ONE;
    });

    // parse immU
    cs.constraint(|cs, a, b, c| {
        let mut pow = F::from(1u32 << 12);
        for i in 12..32 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }

        b[0] = ONE;
        c[cs.var("immU")] = ONE;
    });

    // parse immJ
    cs.constraint(|cs, a, b, c| {
        let mut pow = TWO;
        for i in 21..31 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }
        a[cs.var("inst_20")] = pow;
        pow *= TWO;
        for i in 12..20 {
            a[cs.var(&format!("inst_{i}"))] = pow;
            pow *= TWO;
        }

        a[sb] = F::from(0xfff00000u32);

        b[0] = ONE;
        c[cs.var("immJ")] = ONE;
    });

    cs.seal();
}

fn parse_shamt(cs: &mut R1CS, Y: u32) {
    // we already have lowA from above, compute lowY
    let lowY = Y & 0x1f;
    cs.set_var("lowY", lowY);

    let j = cs.new_local_var("shamt_i");
    cs.w[j] = cs.get_var("opcode=19") * cs.get_var("lowA");

    let j = cs.new_local_var("shamt_r");
    cs.w[j] = cs.get_var("opcode=51") * cs.get_var("lowY");

    if cs.witness_only {
        cs.seal();
        return;
    }

    // constraints
    cs.constraint(|cs, a, b, c| {
        let mut pow = ONE;
        for i in 0..5 {
            a[cs.var(&format!("Y_{i}"))] = pow;
            pow *= TWO;
        }
        b[0] = ONE;
        c[cs.var("lowY")] = ONE;
    });

    cs.mul("shamt_i", "opcode=19", "lowA");
    cs.mul("shamt_r", "opcode=51", "lowY");
    cs.add("shamt", "shamt_i", "shamt_r");
    cs.seal();
}

fn parse_J(cs: &mut R1CS, J: u32) {
    cs.set_var("J", J);
    for j in 1..RV32::MAX_J + 1 {
        cs.set_var(&format!("J={j}"), (j == J).into());
    }

    // used by ALU instructions
    let f30a = cs.new_local_var("f3=0a");
    let f30b = cs.new_local_var("f3=0b");
    let f35a = cs.new_local_var("f3=5a");
    let f35b = cs.new_local_var("f3=5b");

    cs.w[f30a] = cs.get_var("f3=0") * &(ONE - cs.get_var("inst_30"));
    cs.w[f30b] = cs.get_var("f3=0") * cs.get_var("inst_30");
    cs.w[f35a] = cs.get_var("f3=5") * &(ONE - cs.get_var("inst_30"));
    cs.w[f35b] = cs.get_var("f3=5") * cs.get_var("inst_30");

    // constraints
    cs.constraint(|cs, a, b, c| {
        a[0] = ONE;
        a[cs.var("inst_30")] = MINUS;
        b[cs.var("f3=0")] = ONE;
        c[f30a] = ONE;
    });
    cs.mul("f3=0b", "f3=0", "inst_30");
    cs.constraint(|cs, a, b, c| {
        a[0] = ONE;
        a[cs.var("inst_30")] = MINUS;
        b[cs.var("f3=5")] = ONE;
        c[f35a] = ONE;
    });
    cs.mul("f3=5b", "f3=5", "inst_30");

    cs.set_eq("J=1", "opcode=55"); // lui
    cs.set_eq("J=2", "opcode=23"); // auipc
    cs.set_eq("J=3", "opcode=111"); // jal
    cs.set_eq("J=4", "opcode=103"); // jalr

    cs.mul("J=5", "opcode=99", "f3=0"); // beq
    cs.mul("J=6", "opcode=99", "f3=1"); // bne
    cs.mul("J=7", "opcode=99", "f3=4"); // blt
    cs.mul("J=8", "opcode=99", "f3=5"); // bge
    cs.mul("J=9", "opcode=99", "f3=6"); // bltu
    cs.mul("J=10", "opcode=99", "f3=7"); // bgeu

    cs.mul("J=11", "opcode=3", "f3=0"); // lb
    cs.mul("J=12", "opcode=3", "f3=1"); // lh
    cs.mul("J=13", "opcode=3", "f3=2"); // lw
    cs.mul("J=14", "opcode=3", "f3=4"); // lbu
    cs.mul("J=15", "opcode=3", "f3=5"); // lhu

    cs.mul("J=16", "opcode=35", "f3=0"); // sb
    cs.mul("J=17", "opcode=35", "f3=1"); // sh
    cs.mul("J=18", "opcode=35", "f3=2"); // sw

    cs.mul("J=19", "opcode=19", "f3=0"); // addi
    cs.set_var("J=20", 0); // subi does not exist
    cs.mul("J=21", "opcode=19", "f3=1"); // slli
    cs.mul("J=22", "opcode=19", "f3=2"); // slti
    cs.mul("J=23", "opcode=19", "f3=3"); // sltui
    cs.mul("J=24", "opcode=19", "f3=4"); // xori
    cs.mul("J=25", "opcode=19", "f3=5a"); // srli
    cs.mul("J=26", "opcode=19", "f3=5b"); // srai
    cs.mul("J=27", "opcode=19", "f3=6"); // ori
    cs.mul("J=28", "opcode=19", "f3=7"); // andi

    cs.mul("J=29", "opcode=51", "f3=0a"); // add
    cs.mul("J=30", "opcode=51", "f3=0b"); // sub
    cs.mul("J=31", "opcode=51", "f3=1"); // sll
    cs.mul("J=32", "opcode=51", "f3=2"); // slt
    cs.mul("J=33", "opcode=51", "f3=3"); // sltu
    cs.mul("J=34", "opcode=51", "f3=4"); // xor
    cs.mul("J=35", "opcode=51", "f3=5a"); // srl
    cs.mul("J=36", "opcode=51", "f3=5b"); // sra
    cs.mul("J=37", "opcode=51", "f3=6"); // or
    cs.mul("J=38", "opcode=51", "f3=7"); // and

    cs.set_eq("J=39", "opcode=15"); // fence

    let ecall = cs.new_local_var("ecall");
    cs.w[ecall] = (ONE - cs.get_var("inst_12")) * (ONE - cs.get_var("inst_20"));

    cs.constraint(|cs, a, b, c| {
        a[0] = ONE;
        a[cs.var("inst_12")] = MINUS;
        b[0] = ONE;
        b[cs.var("inst_20")] = MINUS;
        c[ecall] = ONE;
    });
    cs.mul("J=40", "opcode=115", "ecall"); // ecall
    cs.mul("J=41", "opcode=115", "inst_20"); // ebreak
    cs.mul("J=42", "opcode=115", "inst_12"); // unimp

    cs.seal();
}

pub fn big_step(vm: &Witness, witness_only: bool) -> R1CS {
    let mut cs = init_cs(vm.regs.pc, &vm.regs.x);
    cs.witness_only = witness_only;

    select_XY(&mut cs, vm.rs1, vm.rs2);

    // check that registers are 32-bit numbers
    cs.to_bits("pc", vm.regs.pc);
    cs.to_bits("X", vm.X);
    cs.to_bits("Y", vm.Y);
    cs.to_bits("I", vm.I);
    cs.to_bits("Z", vm.Z);
    cs.to_bits("PC", vm.PC);

    // control function
    let inst_j = vm.J;
    cs.set_var("rd", vm.rd);
    cs.set_var("rs1", vm.rs1);
    cs.set_var("rs2", vm.rs2);
    cs.set_var("shamt", vm.shamt);
    parse_opc(&mut cs, vm.inst);
    parse_imm(&mut cs, vm.inst);
    parse_shamt(&mut cs, vm.Y);
    parse_J(&mut cs, inst_j);

    // possible values for PC
    cs.set_var("four", 4);
    add_cir(&mut cs, "pc+4", "pc", "four", vm.regs.pc, 4);
    add_cir(&mut cs, "pc+I", "pc", "I", vm.regs.pc, vm.I);

    // process alu first so we get definitions for common values
    alu(&mut cs, vm);

    lui(&mut cs, vm);
    auipc(&mut cs, vm);
    jal(&mut cs, vm);
    jalr(&mut cs, vm);

    br(&mut cs);

    load(&mut cs, vm);
    store(&mut cs, vm);

    misc(&mut cs);

    // constrain Z and PC according to instruction index J
    for j in 1..RV32::MAX_J + 1 {
        #[rustfmt::skip]
        cs.set_var(
            &format!("JZ{j}"),
            if j == inst_j { vm.Z } else { 0 }
        );
        cs.mul(&format!("JZ{j}"), &format!("J={j}"), &format!("Z{j}"));

        #[rustfmt::skip]
        cs.set_var(
            &format!("JPC{j}"),
            if j == inst_j { vm.PC } else { 0 }
        );
        cs.mul(&format!("JPC{j}"), &format!("J={j}"), &format!("PC{j}"));
    }

    // Z = Z[J]
    cs.constraint(|cs, a, b, c| {
        for j in 1..RV32::MAX_J + 1 {
            a[cs.var(&format!("JZ{j}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("Z")] = ONE;
    });

    // PC = PC[J]
    cs.constraint(|cs, a, b, c| {
        for j in 1..RV32::MAX_J + 1 {
            a[cs.var(&format!("JPC{j}"))] = ONE;
        }
        b[0] = ONE;
        c[cs.var("PC")] = ONE;
    });

    // x[rd] = Z
    select_Z(&mut cs, vm.rd);
    cs
}

// We have several different addition circuits, all are built
// with this function

fn add_cir(cs: &mut R1CS, z_name: &str, x_name: &str, y_name: &str, x: u32, y: u32) {
    let O = F::from(0x100000000u64);
    let ON: F = ZERO - O;

    let (z, of) = x.overflowing_add(y);

    let o = if of { ON } else { ZERO };

    // construct witness
    let xj = cs.var(x_name);
    let yj = cs.var(y_name);
    let zj = cs.set_var(z_name, z);

    // note, this is "advice"
    let oj = cs.new_local_var("O");
    cs.w[oj] = o;

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

fn lui(cs: &mut R1CS, vm: &Witness) {
    const J: u32 = (LUI { rd: 0, imm: 0 }).index_j();

    cs.set_var(&format!("Z{J}"), vm.I);
    cs.set_eq(&format!("PC{J}"), "pc+4");
}

fn auipc(cs: &mut R1CS, _vm: &Witness) {
    const J: u32 = (AUIPC { rd: 0, imm: 0 }).index_j();

    cs.set_eq(&format!("Z{J}"), "pc+I");
    cs.set_eq(&format!("PC{J}"), "pc+4");
}

fn jal(cs: &mut R1CS, _vm: &Witness) {
    const J: u32 = (JAL { rd: 0, imm: 0 }).index_j();

    cs.set_eq(&format!("Z{J}"), "pc+4");
    cs.set_eq(&format!("PC{J}"), "pc+I");
}

fn jalr(cs: &mut R1CS, _vm: &Witness) {
    const J: u32 = (JALR { rd: 0, rs1: 0, imm: 0 }).index_j();

    cs.set_eq(&format!("Z{J}"), "pc+4");
    cs.set_eq(&format!("PC{J}"), "X+I");
}

fn alu(cs: &mut R1CS, vm: &Witness) {
    add(cs, vm);
    addi(cs, vm);

    sub(cs, vm);
    subi(cs, vm);

    slt(cs);

    shift(cs, vm);

    bitops(cs, vm);

    let start = (ALUI { aop: ADD, rd: 0, rs1: 0, imm: 0 }).index_j();
    let end = (ALU { aop: AND, rd: 0, rs1: 0, rs2: 0 }).index_j();
    for j in start..end + 1 {
        cs.set_eq(&format!("PC{j}"), "pc+4");
    }
}

fn add(cs: &mut R1CS, vm: &Witness) {
    const J: u32 = (ALU { aop: ADD, rd: 0, rs1: 0, rs2: 0 }).index_j();

    add_cir(cs, "X+Y", "X", "Y", vm.X, vm.Y);
    cs.set_eq(&format!("Z{J}"), "X+Y");
}

fn addi(cs: &mut R1CS, vm: &Witness) {
    const J: u32 = (ALUI { aop: ADD, rd: 0, rs1: 0, imm: 0 }).index_j();

    add_cir(cs, "X+I", "X", "I", vm.X, vm.I);
    cs.set_eq(&format!("Z{J}"), "X+I");
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

fn sub(cs: &mut R1CS, vm: &Witness) {
    const J: u32 = (ALU { aop: SUB, rd: 0, rs1: 0, rs2: 0 }).index_j();

    sub_cir(cs, "X-Y", "X", "Y", vm.X, vm.Y);
    cs.set_eq(&format!("Z{J}"), "X-Y");
}

fn subi(cs: &mut R1CS, vm: &Witness) {
    const J: u32 = (ALUI { aop: SUB, rd: 0, rs1: 0, imm: 0 }).index_j();

    sub_cir(cs, "X-I", "X", "I", vm.X, vm.I);
    cs.set_eq(&format!("Z{J}"), "X-I");
}

fn slt(cs: &mut R1CS) {
    let J = (ALUI { aop: SLT, rd: 0, rs1: 0, imm: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X<sI");

    let J = (ALUI { aop: SLTU, rd: 0, rs1: 0, imm: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X<I");

    let J = (ALU { aop: SLT, rd: 0, rs1: 0, rs2: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X<sY");

    let J = (ALU { aop: SLTU, rd: 0, rs1: 0, rs2: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X<Y");
}

fn branch(cs: &mut R1CS, J: u32, cond_name: &str, inverse_cond_name: &str) {
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
    let pc_four = *cs.get_var("pc+4");
    let PC = if cond { pc_imm } else { pc_four };

    // PC = cond (pc + I) + !cond (pc + 4)
    let left = cs.new_local_var("left");
    cs.w[left] = if cond { pc_imm } else { ZERO };
    cs.mul("left", cond_name, "pc+I");

    let right = cs.new_local_var("right");
    cs.w[right] = if !cond { pc_four } else { ZERO };
    cs.mul("right", inverse_cond_name, "pc+4");

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

fn br(cs: &mut R1CS) {
    let J = (BR { bop: BEQ, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X=Y", "X!=Y");

    let J = (BR { bop: BNE, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X!=Y", "X=Y");

    let J = (BR { bop: BLT, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X<sY", "X>=sY");

    let J = (BR { bop: BGE, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X>=sY", "X<sY");

    let J = (BR { bop: BLTU, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X<Y", "X>=Y");

    let J = (BR { bop: BGEU, rs1: 0, rs2: 0, imm: 0 }).index_j();
    branch(cs, J, "X>=Y", "X<Y");
}

fn load(cs: &mut R1CS, vm: &Witness) {
    for lop in [LB, LH, LW, LBU, LHU] {
        let J = (LOAD { lop, rd: 0, rs1: 0, imm: 0 }).index_j();
        cs.set_var(&format!("Z{J}"), vm.Z);
        cs.set_eq(&format!("PC{J}"), "pc+4");
    }
}

fn store(cs: &mut R1CS, _vm: &Witness) {
    for sop in [SB, SH, SW] {
        let J = (STORE { sop, rs1: 0, rs2: 0, imm: 0 }).index_j();
        cs.set_var(&format!("Z{J}"), 0);
        cs.set_eq(&format!("PC{J}"), "pc+4");
    }
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
        cs.mul(&format!("SZ{amt}"), &format!("shamt={amt}"), &format!("out{amt}"));
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
        cs.mul(&format!("SZ{amt}"), &format!("shamt={amt}"), &format!("out{amt}"));
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

fn shift(cs: &mut R1CS, vm: &Witness) {
    selector(cs, "shamt", 32, vm.shamt);

    let J = (ALUI { aop: SLL, rd: 0, rs1: 0, imm: 0 }).index_j();
    shift_left(cs, &format!("Z{J}"), vm.X, vm.shamt);

    let J = (ALUI { aop: SRL, rd: 0, rs1: 0, imm: 0 }).index_j();
    shift_right(cs, &format!("Z{J}"), vm.X, vm.shamt, false);

    let J = (ALUI { aop: SRA, rd: 0, rs1: 0, imm: 0 }).index_j();
    shift_right(cs, &format!("Z{J}"), vm.X, vm.shamt, true);

    let J = (ALU { aop: SLL, rd: 0, rs1: 0, rs2: 0 }).index_j();
    shift_left(cs, &format!("Z{J}"), vm.X, vm.shamt);

    let J = (ALU { aop: SRL, rd: 0, rs1: 0, rs2: 0 }).index_j();
    shift_right(cs, &format!("Z{J}"), vm.X, vm.shamt, false);

    let J = (ALU { aop: SRA, rd: 0, rs1: 0, rs2: 0 }).index_j();
    shift_right(cs, &format!("Z{J}"), vm.X, vm.shamt, true);
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

fn bitops(cs: &mut R1CS, vm: &Witness) {
    fn bit(x: u32, bit: u32) -> bool {
        ((x >> bit) & 1) != 0
    }

    // and
    let XY = vm.X & vm.Y;
    let XI = vm.X & vm.I;
    cs.to_bits("X&Y", XY);
    cs.to_bits("X&I", XI);
    for i in 0..32 {
        cs.set_bit(&format!("X&Y_{i}"), bit(XY, i));
        cs.mul(&format!("X&Y_{i}"), &format!("X_{i}"), &format!("Y_{i}"));

        cs.set_bit(&format!("X&I_{i}"), bit(XI, i));
        cs.mul(&format!("X&I_{i}"), &format!("X_{i}"), &format!("I_{i}"));
    }

    let J = (ALUI { aop: AND, rd: 0, rs1: 0, imm: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X&I");

    let J = (ALU { aop: AND, rd: 0, rs1: 0, rs2: 0 }).index_j();
    cs.set_eq(&format!("Z{J}"), "X&Y");

    // or
    let J = (ALUI { aop: OR, rd: 0, rs1: 0, imm: 0 }).index_j();
    bitop(cs, &format!("Z{J}"), "I", vm.X | vm.I, MINUS);

    let J = (ALU { aop: OR, rd: 0, rs1: 0, rs2: 0 }).index_j();
    bitop(cs, &format!("Z{J}"), "Y", vm.X | vm.Y, MINUS);

    // xor
    let J = (ALUI { aop: XOR, rd: 0, rs1: 0, imm: 0 }).index_j();
    bitop(cs, &format!("Z{J}"), "I", vm.X ^ vm.I, F::from(-2));

    let J = (ALU { aop: XOR, rd: 0, rs1: 0, rs2: 0 }).index_j();
    bitop(cs, &format!("Z{J}"), "Y", vm.X ^ vm.Y, F::from(-2));
}

fn misc(cs: &mut R1CS) {
    let mut nop = |J: u32| {
        cs.set_var(&format!("Z{J}"), 0);
        cs.set_eq(&format!("PC{J}"), "pc+4");
    };

    nop(FENCE.index_j());
    nop(ECALL.index_j());
    nop(EBREAK.index_j());

    // unimp is special
    let J = UNIMP.index_j();
    cs.set_var(&format!("Z{J}"), 0);
    cs.set_eq(&format!("PC{J}"), "pc");
}

#[cfg(test)]
mod test {
    use nexus_riscv::rv32::parse::*;
    use super::*;

    #[test]
    fn test_parse_opc() {
        #[rustfmt::skip]
        let opc = [
            (OPC_LUI,   1, 0, 0 ),
            (OPC_AUIPC, 1, 0, 0 ),
            (OPC_JAL,   1, 0, 0 ),
            (OPC_JALR,  1, 1, 0 ),
            (OPC_BR,    0, 1, 1 ),
            (OPC_LOAD,  1, 1, 0 ),
            (OPC_STORE, 0, 1, 1 ),
            (OPC_ALUI,  1, 1, 0 ),
            (OPC_ALU,   1, 1, 1 ),
            (OPC_FENCE, 1, 1, 0 ),
            (OPC_ECALL, 0, 0, 0 ),
        ];
        for (op, has_rd, has_rs1, has_rs2) in opc {
            for rd in [0, 1, 31] {
                for rs1 in [0, 1, 31] {
                    for rs2 in [0, 1, 31] {
                        // build instruction word
                        let inst: u32 = (rs2 << 20) | (rs1 << 15) | (rd << 7) | op;

                        //println!("inst {inst:x}");
                        let mut cs = R1CS::default();
                        cs.set_var("rd", rd);
                        cs.set_var("rs1", rs1);
                        cs.set_var("rs2", rs2);
                        parse_opc(&mut cs, inst);
                        assert!(cs.is_sat());

                        if has_rs2 == 0 {
                            break;
                        }
                    }
                    if has_rs1 == 0 {
                        break;
                    }
                }
                if has_rd == 0 {
                    break;
                }
            }
        }
    }

    #[test]
    fn test_parse_imm() {
        let tests: &[(u32, u32)] = &[
            (0x00055037, 0x55000),    // lui x0, 0x55    type=U
            (0x0040006f, 4),          // jal x0, 4       type=J
            (0x00400067, 4),          // jalr x0, x0, 4  type=I
            (0x00000263, 4),          // beq x0, x0, 4   type=B
            (0x000020a3, 1),          // sw x0, x0, 1    type=S
            (0xfe002fa3, 0xffffffff), // sw x0, x0, -1   type=S
            (0x40000033, 0),          // sub x0, x0, x0  type=R (f7=1)
            (0xfff00013, 0xffffffff), // addi x0, x0, -1 type=A (f7=0)
            (0x40105013, 1),          // srai x0, x0, 1  type=A (f7=1)
        ];
        for &(inst, i) in tests {
            let mut cs = R1CS::default();
            cs.set_var("rd", 0);
            cs.set_var("rs1", 0);
            cs.set_var("rs2", 0);
            cs.to_bits("I", i);
            parse_opc(&mut cs, inst);
            parse_imm(&mut cs, inst);
            assert!(cs.is_sat());
        }
    }

    #[test]
    fn test_select_XY() {
        let regs: [u32; 32] = core::array::from_fn(|i| i as u32);
        for x in [0, 1, 2, 31] {
            for y in [0, 6, 13] {
                let mut cs = init_cs(0, &regs);
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
        for i in 0..32 {
            let mut cs = init_cs(0, &regs);
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
                vm.I = y;
                let mut cs = R1CS::default();
                cs.set_var("X", x);
                cs.set_var("Y", y);
                cs.set_var("I", y);
                add(&mut cs, &vm);
                addi(&mut cs, &vm);
                assert!(cs.is_sat());
                assert!(cs.get_var("Z29") == &F::from(x.overflowing_add(y).0));
                assert!(cs.get_var("Z19") == &F::from(x.overflowing_add(y).0));
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
                vm.I = y;
                let mut cs = R1CS::default();
                cs.set_var("X", x);
                cs.set_var("Y", y);
                cs.set_var("I", y);
                cs.to_bits("X", x);
                cs.to_bits("Y", y);
                cs.to_bits("I", y);
                sub(&mut cs, &vm);
                subi(&mut cs, &vm);
                assert!(cs.is_sat());
                assert!(cs.get_var("Z30") == &F::from(x.overflowing_sub(y).0));
                assert!(cs.get_var("Z20") == &F::from(x.overflowing_sub(y).0));

                assert!(cs.get_var("X<Y") == &F::from(x < y));
                assert!(cs.get_var("X>=Y") == &F::from(x >= y));
                assert!(cs.get_var("X=Y") == &F::from(x == y));
                assert!(cs.get_var("X!=Y") == &F::from(x != y));

                assert!(cs.get_var("X<sY") == &F::from((x as i32) < (y as i32)));
                assert!(cs.get_var("X>=sY") == &F::from((x as i32) >= (y as i32)));

                assert!(cs.get_var("X<I") == &F::from(x < y));
                assert!(cs.get_var("X>=I") == &F::from(x >= y));
                assert!(cs.get_var("X=I") == &F::from(x == y));
                assert!(cs.get_var("X!=I") == &F::from(x != y));

                assert!(cs.get_var("X<sI") == &F::from((x as i32) < (y as i32)));
                assert!(cs.get_var("X>=sI") == &F::from((x as i32) >= (y as i32)));
            }
        }
    }

    #[test]
    fn test_br() {
        let mut cs = R1CS::default();
        cs.set_var("pc+I", 1);
        cs.set_var("pc+4", 0);
        cs.set_var("X=Y", 0);
        cs.set_var("X!=Y", 1);
        cs.set_var("X<Y", 1);
        cs.set_var("X>=Y", 0);
        cs.set_var("X<sY", 1);
        cs.set_var("X>=sY", 0);
        br(&mut cs);
        assert!(cs.is_sat());
        assert_eq!(cs.get_var("PC5"), &ZERO);
        assert_eq!(cs.get_var("PC6"), &ONE);
        assert_eq!(cs.get_var("PC7"), &ONE);
        assert_eq!(cs.get_var("PC8"), &ZERO);
        assert_eq!(cs.get_var("PC9"), &ONE);
        assert_eq!(cs.get_var("PC10"), &ZERO);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_shift() {
        let mut vm = Witness::default();
        vm.inst = 0x00000013; // nop
        for x in [0x7aaaaaaa, 0xf5555555] {
            for a in [0, 1, 10, 13, 30, 31] {
                vm.X = x;
                vm.shamt = a;
                let mut cs = R1CS::default();
                cs.to_bits("X", x);

                shift(&mut cs, &vm);

                assert!(cs.is_sat());

                assert!(cs.get_var("Z21") == &F::from(x << a));
                assert!(cs.get_var("Z25") == &F::from(x >> a));
                assert!(cs.get_var("Z26") == &F::from(((x as i32) >> a) as u32));

                assert!(cs.get_var("Z31") == &F::from(x << a));
                assert!(cs.get_var("Z35") == &F::from(x >> a));
                assert!(cs.get_var("Z36") == &F::from(((x as i32) >> a) as u32));
            }
        }
    }

    #[test]
    fn test_bitops() {
        let mut vm = Witness::default();
        for x in [0u32, 0xaaaaaaaa, 0x55555555, 0xffffffff] {
            for y in [0u32, 0xaaaaaaaa, 0x55555555, 0xffffffff] {
                let i = y.overflowing_add(7).0;
                vm.X = x;
                vm.Y = y;
                vm.I = i;
                let mut cs = R1CS::default();
                cs.to_bits("X", x);
                cs.to_bits("Y", y);
                cs.to_bits("I", i);

                bitops(&mut cs, &vm);

                assert!(cs.is_sat());

                assert!(cs.get_var("Z28") == &F::from(x & i));
                assert!(cs.get_var("Z38") == &F::from(x & y));

                assert!(cs.get_var("Z27") == &F::from(x | i));
                assert!(cs.get_var("Z37") == &F::from(x | y));

                assert!(cs.get_var("Z24") == &F::from(x ^ i));
                assert!(cs.get_var("Z34") == &F::from(x ^ y));
            }
        }
    }
}
