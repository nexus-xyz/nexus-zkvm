use super::*;
use std::fmt::{Debug, Display, Formatter, Result};

fn lower<T: Debug>(f: &mut Formatter<'_>, x: T) -> Result {
    write!(f, "{}", format!("{:?}", x).to_lowercase())
}

macro_rules! display_lower {
    ($t:ty) => {
        impl Display for $t {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result {
                lower(f, self)
            }
        }
    };
}

display_lower!(BOP);
display_lower!(LOP);
display_lower!(SOP);
display_lower!(AOP);

impl Display for RV32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            LUI { rd, imm } => write!(f, "lui x{}, {:x}", rd, imm),
            AUIPC { rd, imm } => write!(f, "auipc x{}, {:x}", rd, imm),
            JAL { rd, imm } => write!(f, "jal x{}, {:x}", rd, imm),
            JALR { rd, rs1, imm } => write!(f, "jalr x{}, x{}, {:x}", rd, rs1, imm),
            BR { bop, rs1, rs2, imm } => write!(f, "{} x{}, x{}, {:x}", bop, rs1, rs2, imm),
            LOAD { lop, rd, rs1, imm } => write!(f, "{} x{}, x{}, {:x}", lop, rd, rs1, imm),
            STORE { sop, rs1, rs2, imm } => write!(f, "{} x{}, x{}, {:x}", sop, rs1, rs2, imm),
            ALUI { aop, rd, rs1, imm } => write!(f, "{}i x{}, x{}, {:x}", aop, rd, rs1, imm),
            ALU { aop, rd, rs1, rs2 } => write!(f, "{} x{}, x{}, x{}", aop, rd, rs1, rs2),
            ECALL { rd } => write!(f, "ecall x{}", rd),
            EBREAK { rd } => write!(f, "ebreak x{}", rd),
            _ => lower(f, self),
        }
    }
}

impl Display for Inst {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let w = match f.width() {
            Some(w) if w > 18 => w - 18,
            Some(_) => 0,
            None => 30,
        };
        write!(
            f,
            "{:07x} {:08x} {:w$}",
            self.pc,
            self.word,
            format!("{}", self.inst)
        )
    }
}
