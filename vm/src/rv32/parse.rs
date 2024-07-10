//! A basic parser for RISC-V, RV32I

use super::*;
use crate::error::*;
use NexusVMError::*;

fn bits(val: u32, start: u32, end: u32) -> u32 {
    debug_assert!(start <= end);
    debug_assert!(end < 32);

    (val << (31 - end)) >> (31 - end + start)
}

#[rustfmt::skip]
macro_rules! field {
    ($f:ident, $start:literal, $end:literal) => {
        #[doc=concat!("extract ", stringify!($f),
                      " field from instruction word, bits ",
                      $start, "-", $end)]
        pub fn $f(word: u32) -> u32 {
            bits(word, $start, $end)
        }
    };
}

// instruction encodings pg. 16 (and 18 for shamt)

field!(opcode, 0, 6);
field!(funct3, 12, 14);
field!(funct7, 25, 31);
field!(shamt, 20, 24);
field!(rd, 7, 11);
field!(rs1, 15, 19);
field!(rs2, 20, 24);

// encoding of immediate values pg. 16

fn signed(word: u32) -> bool {
    (word & 0x80000000) != 0
}

/// extract immediate from instruction of type I
pub fn immI(word: u32) -> u32 {
    let mut imm = if signed(word) { 0xfffff800 } else { 0 };
    imm |= bits(word, 20, 30);
    imm
}

/// extract immediate from instruction of type S
pub fn immS(word: u32) -> u32 {
    let mut imm = if signed(word) { 0xfffff800 } else { 0 };
    imm |= bits(word, 25, 30) << 5;
    imm |= bits(word, 7, 11);
    imm
}

/// extract immediate from instruction of type B
pub fn immB(word: u32) -> u32 {
    let mut imm = if signed(word) { 0xfffff000 } else { 0 };
    imm |= bits(word, 7, 7) << 11;
    imm |= bits(word, 25, 30) << 5;
    imm |= bits(word, 8, 11) << 1;
    imm
}

/// extract immediate from instruction of type U
pub fn immU(word: u32) -> u32 {
    word & 0xfffff000
}

/// extract immediate from instruction of type J
pub fn immJ(word: u32) -> u32 {
    let mut imm = if signed(word) { 0xfff00000 } else { 0 };
    imm |= bits(word, 12, 19) << 12;
    imm |= bits(word, 20, 20) << 11;
    imm |= bits(word, 21, 30) << 1;
    imm
}

// parsing of branch operation type pg. 22

fn bop(word: u32) -> Option<BOP> {
    let res = match funct3(word) {
        0b000 => BEQ,
        0b001 => BNE,
        0b100 => BLT,
        0b101 => BGE,
        0b110 => BLTU,
        0b111 => BGEU,
        _ => return None,
    };
    Some(res)
}

// parsing of load and store widths pg. 24-25

fn lop(word: u32) -> Option<LOP> {
    let res = match funct3(word) {
        0b000 => LB,
        0b001 => LH,
        0b010 => LW,
        0b100 => LBU,
        0b101 => LHU,
        _ => return None,
    };
    Some(res)
}

fn sop(word: u32) -> Option<SOP> {
    let res = match funct3(word) {
        0b000 => SB,
        0b001 => SH,
        0b010 => SW,
        _ => return None,
    };
    Some(res)
}

// parsing of arithmetic operations pg. 18-20

fn aop(word: u32) -> Option<AOP> {
    let res = match (opcode(word), funct3(word), funct7(word)) {
        (0b0110011, 0b000, 0b0100000) => SUB,
        (_, 0b000, _) => ADD,
        (_, 0b001, _) => SLL,
        (_, 0b010, _) => SLT,
        (_, 0b011, _) => SLTU,
        (_, 0b100, _) => XOR,
        (_, 0b101, 0b0000000) => SRL,
        (_, 0b101, 0b0100000) => SRA,
        (_, 0b110, _) => OR,
        (_, 0b111, _) => AND,
        _ => return None,
    };
    Some(res)
}

/// extract immediate from ALU instruction
pub fn immA(word: u32) -> u32 {
    match funct3(word) {
        0b001 | 0b101 => shamt(word),
        _ => immI(word),
    }
}

// instruction parsing by opcode

#[allow(clippy::unusual_byte_groupings)]
#[rustfmt::skip]
mod opcodes {
    pub const OPC_LUI   : u32 = 0b_011_0111;
    pub const OPC_AUIPC : u32 = 0b_001_0111;
    pub const OPC_JAL   : u32 = 0b_110_1111;
    pub const OPC_JALR  : u32 = 0b_110_0111;
    pub const OPC_BR    : u32 = 0b_110_0011;
    pub const OPC_LOAD  : u32 = 0b_000_0011;
    pub const OPC_STORE : u32 = 0b_010_0011;
    pub const OPC_ALUI  : u32 = 0b_001_0011;
    pub const OPC_ALU   : u32 = 0b_011_0011;
    pub const OPC_FENCE : u32 = 0b_000_1111;
    pub const OPC_ECALL : u32 = 0b_111_0011; // also captures EBREAK and UNIMP
}
pub use opcodes::*;

fn assert_option(exp: bool) -> Option<()> {
    if exp {
        Some(())
    } else {
        None
    }
}

// parse a 32-bit word as an instruction
pub(crate) fn parse_u32(word: u32) -> Option<RV32> {
    let inst = match opcode(word) {
        OPC_LUI => LUI { rd: rd(word), imm: immU(word) },
        OPC_AUIPC => AUIPC { rd: rd(word), imm: immU(word) },
        OPC_JAL => JAL { rd: rd(word), imm: immJ(word) },
        OPC_JALR => {
            assert_option(funct3(word) == 0)?;
            JALR {
                rd: rd(word),
                rs1: rs1(word),
                imm: immI(word),
            }
        }
        OPC_BR => BR {
            bop: bop(word)?,
            rs1: rs1(word),
            rs2: rs2(word),
            imm: immB(word),
        },

        OPC_LOAD => LOAD {
            lop: lop(word)?,
            rd: rd(word),
            rs1: rs1(word),
            imm: immI(word),
        },
        OPC_STORE => STORE {
            sop: sop(word)?,
            rs1: rs1(word),
            rs2: rs2(word),
            imm: immS(word),
        },

        OPC_ALUI => ALUI {
            aop: aop(word)?,
            rd: rd(word),
            rs1: rs1(word),
            imm: immA(word),
        },
        OPC_ALU => ALU {
            aop: aop(word)?,
            rd: rd(word),
            rs1: rs1(word),
            rs2: rs2(word),
        },

        OPC_FENCE => FENCE,

        OPC_ECALL => {
            match word >> 12 {
                0x00000 => ECALL { rd: rd(word) },
                0x00100 => EBREAK { rd: rd(word) },
                0xc0001 => UNIMP, // csrrw x0, cycle, x0
                _ => return None,
            }
        }

        _ => return None,
    };
    Some(inst)
}

// compute instruction size from first two bytes (pg. 8)

fn inst_size(b0: u8, b1: u8) -> u32 {
    fn ax(b: u8, n: u8) -> bool {
        ((b & n) ^ n) != 0
    }

    if ax(b0, 0b00000011) {
        2
    } else if ax(b0, 0b00011111) {
        4
    } else if ax(b0, 0b00111111) {
        6
    } else if ax(b0, 0b01111111) {
        8
    } else if ax(b1, 0b01110000) {
        (10 + 2 * ((b1 >> 4) & 0b111)) as u32
    } else {
        0
    }
}

/// translate RV32i instructions to RV32Nexus instructions
fn translate_nexus(word: u32) -> u32 {
    match word {
        // ecall     // ebreak
        0x00000073 | 0x00100073 => word | (0b1010 << 7), // set rd = 10
        _ => word,
    }
}

/// parse a single instruction from a byte array
pub fn parse_inst(pc: u32, mem: &[u8]) -> Result<Inst> {
    if mem.len() < 2 {
        return Err(PartialInstruction(pc));
    }

    let sz = inst_size(mem[0], mem[1]);
    if mem.len() < (sz as usize) {
        return Err(PartialInstruction(pc));
    }

    if sz != 4 {
        return Err(InvalidSize(pc, sz));
    }

    let word = ((mem[3] as u32) << 24)
        | ((mem[2] as u32) << 16)
        | ((mem[1] as u32) << 8)
        | (mem[0] as u32);

    let word = translate_nexus(word);

    match parse_u32(word) {
        None => Err(InvalidInstruction(pc, word)),
        Some(inst) => Ok(Inst { pc, len: sz, word, inst }),
    }
}

/// parse a sequence of instructions from a byte array
pub fn parse_buf(pc: u32, mem: &[u8]) -> Result<Vec<Inst>> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < mem.len() {
        let inst = parse_inst(pc + i as u32, &mem[i..])?;
        i += inst.len as usize;
        v.push(inst);
    }
    Ok(v)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bits() {
        assert_eq!(bits(0b10011101, 0, 0), 0b1);
        assert_eq!(bits(0b10011101, 0, 1), 0b01);
        assert_eq!(bits(0b10011101, 0, 2), 0b101);
        assert_eq!(bits(0b10011101, 0, 3), 0b1101);
        assert_eq!(bits(0b10011101, 0, 4), 0b11101);
        assert_eq!(bits(0b10011101, 1, 4), 0b1110);
        assert_eq!(bits(0b10011101, 2, 4), 0b111);
        assert_eq!(bits(0b10011101, 3, 4), 0b11);
        assert_eq!(bits(0b10011101, 4, 4), 0b1);

        assert_eq!(bits(0xcc000000, 0, 31), 0xcc000000);
        assert_eq!(bits(0xcc000000, 31, 31), 0x1);
        assert_eq!(bits(0xcc000000, 28, 31), 0xc);
        assert_eq!(bits(0xcc000000, 24, 27), 0xc);
        assert_eq!(bits(0xcc000000, 24, 31), 0xcc);
        assert_eq!(bits(0xcc000000, 26, 31), 0x33);
        assert_eq!(bits(0xcc000000, 26, 30), 0x13);

        assert_eq!(bits(0b101010101010, 7, 11), 0b10101);
        assert_eq!(bits(0x80001837, 7, 11), 16);
    }

    #[test]
    fn test_lui_auipc() {
        let imms = [0, 0x80001, 0x80f01, 0xfffff];
        for rd in 0..31 {
            for imm in imms {
                let imm = imm << 12;
                let word = imm | (rd << 7) | 0x37;
                let inst = LUI { rd, imm };
                assert_eq!(parse_u32(word), Some(inst));

                let word = imm | (rd << 7) | 0x17;
                let inst = AUIPC { rd, imm };
                assert_eq!(parse_u32(word), Some(inst));
            }
        }
    }

    #[test]
    fn test_jal() {
        let offs = [0, 0x00400, 0xff9ff, 0x0ac00, 0xfd9ff];
        let imms = [0, 4, 0xfffffff8, 0xac, 0xffffffd8];
        for rd in 0..31 {
            for i in 0..offs.len() {
                let off = offs[i];
                let imm = imms[i];
                let word = (off << 12) | (rd << 7) | 0x6f;
                let inst = JAL { rd, imm };
                assert_eq!(parse_u32(word), Some(inst));
            }
        }
    }

    #[test]
    fn test_jalr() {
        let offs = [1, 0xfff, 0xccc, 0x333];
        let imms = [1, 0xffffffff, 0xfffffccc, 0x333];
        for rd in 0..31 {
            for rs1 in 0..31 {
                for i in 0..offs.len() {
                    let off = offs[i];
                    let imm = imms[i];
                    let word = (off << 20) | (rs1 << 15) | (rd << 7) | 0x67;
                    let inst = JALR { rd, rs1, imm };
                    assert_eq!(parse_u32(word), Some(inst));
                }
            }
        }
    }

    #[test]
    fn test_br() {
        // check immB
        let imm = 0xfe000ee3;
        assert_eq!(immB(imm), 0xfffffffc);
        let imm = imm ^ 0x80000000;
        assert_eq!(immB(imm), 0xffc);

        let cond_v = [0, 1, 4, 5, 6, 7];
        let cond_e = [BEQ, BNE, BLT, BGE, BLTU, BGEU];

        for c in 0..cond_v.len() {
            let v = cond_v[c];
            let e = cond_e[c];
            for rs1 in 0..31 {
                for rs2 in 0..32 {
                    let word = imm | (v << 12) | (rs1 << 15) | (rs2 << 20);
                    let inst = BR { bop: e, rs1, rs2, imm: 0xffc };
                    assert_eq!(parse_u32(word), Some(inst));
                }
            }
        }
    }

    #[test]
    fn test_load() {
        let offs = [0u32, 1, 0xfff];
        let imms = [0u32, 1, 0xffffffff];
        let widths = [0, 1, 2, 4, 5];
        let lops = [LB, LH, LW, LBU, LHU];

        for i in 0..offs.len() {
            for j in 0..widths.len() {
                for rd in 0..31 {
                    for rs1 in 0..31 {
                        let off = offs[i] << 20;
                        let imm = imms[i];
                        let word = off | (rs1 << 15) | (widths[j] << 12) | (rd << 7) | 3;
                        let inst = LOAD { lop: lops[j], rd, rs1, imm };
                        assert_eq!(parse_u32(word), Some(inst));
                    }
                }
            }
        }
    }

    #[test]
    fn test_store() {
        // check immS
        let off = 0xfe000f80;
        assert_eq!(immS(off), 0xffffffff);
        let off = 0x7e000f80;
        assert_eq!(immS(off), 0x7ff);
        let word = off | 0x23;

        let widths = [0, 1, 2];
        let sops = [SB, SH, SW];

        for j in 0..widths.len() {
            for rs1 in 0..31 {
                for rs2 in 0..31 {
                    let word = word | (rs1 << 15) | (widths[j] << 12) | (rs2 << 20);
                    let inst = STORE { sop: sops[j], rs1, rs2, imm: 0x7ff };
                    assert_eq!(parse_u32(word), Some(inst));
                }
            }
        }
    }

    #[test]
    fn test_alu() {
        let word = 0x01f00013;
        assert_eq!(immI(word), 31);

        let ops = [ADD, SLL, SLT, SLTU, XOR, SRL, OR, AND];

        for rd in 0..31 {
            for rs1 in 0..31 {
                for f3 in 0..7u32 {
                    let op = ops[f3 as usize];
                    let word = word | (rs1 << 15) | (f3 << 12) | (rd << 7);
                    let inst = ALUI { aop: op, rd, rs1, imm: 31 };
                    assert_eq!(parse_u32(word), Some(inst));

                    let inst = ALU { aop: op, rd, rs1, rs2: 31 };
                    assert_eq!(parse_u32(word | 0x20), Some(inst));

                    if op == SRL {
                        let word = word | 0x40000000;
                        let inst = ALUI { aop: SRA, rd, rs1, imm: 31 };
                        assert_eq!(parse_u32(word), Some(inst));

                        let inst = ALU { aop: SRA, rd, rs1, rs2: 31 };
                        assert_eq!(parse_u32(word | 0x20), Some(inst));
                    }

                    if op == ADD {
                        let word = word | 0x40000000;
                        let inst = ALU { aop: SUB, rd, rs1, rs2: 31 };
                        assert_eq!(parse_u32(word | 0x20), Some(inst));
                    }
                }
            }
        }
    }

    #[test]
    fn test_nexus() {
        assert_eq!(parse_u32(0x00000573), Some(ECALL { rd: 10 }));
        assert_eq!(parse_u32(0x00100573), Some(EBREAK { rd: 10 }));
    }

    #[test]
    fn test_misc() {
        assert_eq!(parse_u32(0), None);
        assert_eq!(parse_u32(0xc0001073), Some(UNIMP));
    }
}
