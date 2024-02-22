//! Nexus VM Instructions.
//!
//! Instructions all have a 64-bit encoding. The encoding is described
//! below with each field and field length (in bits) specified:
//!
//! ```text
//! | immediate(32) | rs2(5) | rs1(5) | rd(5) | unused(9) | opcode(8) |
//! ```
//!
//! The opcode occupies the least-significant bits.
//! The rd field is the destination register, and rs1, and rs2 are the argument
//! registers. An immediate value occupies the most-significant word.
//! The opcode specifies the instruction; the availabe opcodes are contained
//! in the `Opcode` enumeration.

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

/// Instruction opcodes for the Nexus VM.
#[repr(u8)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum Opcode {
    /// no operation
    #[default]
    NOP = 0x01,

    /// halt execution, pc is not updated
    HALT = 0x02,

    /// system call
    SYS = 0x03,

    /// jump and link, jump to rs1+imm, store pc+8 in rd
    JAL = 0x10,

    /// branch to pc+imm if rs1 == rs2
    BEQ = 0x11,
    /// branch to pc+imm if rs1 != rs2
    BNE = 0x12,
    /// branch to pc+imm if rs1 < rs2 (signed compare)
    BLT = 0x13,
    /// branch to pc+imm if rs1 >= rs2 (signed compare)
    BGE = 0x14,
    /// branch to pc+imm if rs1 < rs2 (unsigned compare)
    BLTU = 0x15,
    /// branch to pc+imm if rs1 >= rs2 (unsigned compare)
    BGEU = 0x16,

    /// load byte at address rs1+imm, sign-extended
    LB = 0x20,
    /// load half-word at address rs1+imm, sign-extended
    LH = 0x21,
    /// load word at address rs1+imm, sign-extended
    LW = 0x22,
    /// load byte at address rs1+imm, zero-extended
    LBU = 0x23,
    /// load half-word at address rs1+imm, zero-extended
    LHU = 0x24,

    /// store byte in rs2 at address rs1+imm
    SB = 0x30,
    /// store half-word in rs2 at address rs1+imm
    SH = 0x31,
    /// store word in rs2 at address rs1+imm
    SW = 0x32,

    /// rd = rs1 + rs2 + imm
    ADD = 0x40,
    /// rd = rs1 - rs2 + imm
    SUB = 0x41,
    /// rd = rs1 < (rs2 + imm)
    SLT = 0x42,
    /// rd = rs1 < (rs2 + imm) (unsigned comparison)
    SLTU = 0x43,
    /// rd = rs1 << (rs2 + imm)
    SLL = 0x44,
    /// rd = rs1 >> (rs2 + imm)
    SRL = 0x45,
    /// rd = rs1 >> (rs2 + imm)  (arithmetic)
    SRA = 0x46,
    /// rd = rs1 | (rs2 + imm)
    OR = 0x47,
    /// rd = rs1 & (rs2 + imm)
    AND = 0x48,
    /// rd = rs1 ^ (rs2 + imm)
    XOR = 0x49,
}

#[repr(u8)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum Width {
    #[default]
    B = 0,
    H = 1,
    W = 2,
    BU = 3,
    HU = 4,
}

/// NexusVM instruction
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct Inst {
    /// Instruction opcode
    pub opcode: Opcode,
    /// destination register
    pub rd: u8,
    /// argument register 1
    pub rs1: u8,
    /// argument register 2
    pub rs2: u8,
    /// immediate value
    pub imm: u32,
}

impl std::fmt::Display for Inst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opc = format!("{:?}", self.opcode).to_lowercase();
        write!(
            f,
            "{opc} x{}, x{}, x{}, 0x{:x}",
            self.rd, self.rs1, self.rs2, self.imm
        )
    }
}

impl TryFrom<Opcode> for Width {
    type Error = &'static str;
    fn try_from(opcode: Opcode) -> Result<Self, Self::Error> {
        let tag = opcode as u8;
        if tag & 0xf0 != 0x20 && tag & 0xf0 != 0x30 {
            return Err("no width for opcode {opcode:?}");
        }
        Self::from_u8(tag & 7).ok_or("Opcode to Width conversion")
    }
}

impl From<Inst> for u64 {
    fn from(val: Inst) -> u64 {
        let opc = val.opcode as u64;
        let rd = (val.rd as u64) << 17;
        let rs1 = (val.rs1 as u64) << 22;
        let rs2 = (val.rs2 as u64) << 27;
        let imm = (val.imm as u64) << 32;

        imm | rs2 | rs1 | rd | opc
    }
}

impl FromPrimitive for Inst {
    fn from_i64(n: i64) -> Option<Self> {
        Self::from_u64(n as u64)
    }

    fn from_u64(n: u64) -> Option<Self> {
        Some(Inst {
            opcode: Opcode::from_u64(n & 0xff)?,
            rd: ((n >> 17) & 0x1f) as u8,
            rs1: ((n >> 22) & 0x1f) as u8,
            rs2: ((n >> 27) & 0x1f) as u8,
            imm: (n >> 32) as u32,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use Opcode::*;
    use Width::*;

    #[test]
    fn test_from_into() {
        for i in 0u8..255 {
            match Opcode::from_u8(i) {
                None => (),
                Some(o) => {
                    println!("{i:x} {o:?}");
                    let inst1 = Inst {
                        opcode: o,
                        rd: 0x1f,
                        rs1: 0x11,
                        rs2: 0x12,
                        imm: 0x80000001,
                    };
                    let dword: u64 = inst1.into();
                    let inst2 = Inst::from_u64(dword).unwrap();
                    assert_eq!(inst1, inst2);
                }
            }
        }
    }

    #[test]
    fn test_width() {
        assert_eq!(Width::try_from(LB).unwrap(), B);
        assert_eq!(Width::try_from(LH).unwrap(), H);
        assert_eq!(Width::try_from(LW).unwrap(), W);
        assert_eq!(Width::try_from(LHU).unwrap(), HU);
        assert_eq!(Width::try_from(LBU).unwrap(), BU);

        assert_eq!(Width::try_from(SB).unwrap(), B);
        assert_eq!(Width::try_from(SH).unwrap(), H);
        assert_eq!(Width::try_from(SW).unwrap(), W);
    }
}
