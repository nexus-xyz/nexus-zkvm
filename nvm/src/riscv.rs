// Note: this module will be migrated to the riscv crate
// so that the NVM crate does not depend on riscv.
// It is here for now to avoid disturbing the riscv crate
// until the final PR.

use std::path::Path;
use std::fs::read;
use num_traits::FromPrimitive;

use elf::{
    abi::{PT_LOAD, PF_X},
    endian::LittleEndian,
    segment::ProgramHeader,
    ElfBytes,
};

use nexus_riscv::rv32::{RV32, Inst as RVInst, parse::parse_buf};

use crate::error::Result;
use crate::instructions::{Inst, Opcode, Opcode::*};

#[inline]
fn add32(a: u32, b: u32) -> u32 {
    a.overflowing_add(b).0
}

#[inline]
fn mul32(a: u32, b: u32) -> u32 {
    a.overflowing_mul(b).0
}

// Translate a RV32 instruction to an NVM instruction.
// We use the start and end of the code segment to heuristically,
// decide how to handle PC-relative computations.
// This technique works for programs built with nexus_rt, but is
// not generally correct (general correctness would require a
// more fullsome compilation pass, which is future work).
//
// Note: the from_u8's cannot fail if the test cases
// in this module all pass: the unwrap's are safe.
fn translate_inst(start: u32, end: u32, rv: RVInst) -> Inst {
    let RVInst { pc, len: _, word: _, inst: rv } = rv;

    let mut inst = Inst::default();
    match rv {
        RV32::LUI { rd, imm } => {
            inst.opcode = ADD;
            inst.rd = rd as u8;
            inst.imm = imm;
        }
        RV32::AUIPC { rd, imm } => {
            inst.opcode = ADD;
            inst.rd = rd as u8;
            let res = add32(pc, imm);
            if res >= start && res < end {
                // assume address of label and adjust
                inst.imm = add32(pc, mul32(imm, 2));
            } else {
                inst.imm = res;
            }
        }
        RV32::JAL { rd, imm } => {
            inst.opcode = JAL;
            inst.rd = rd as u8;
            inst.imm = add32(pc, mul32(imm, 2));
        }
        RV32::JALR { rd, rs1, imm } => {
            inst.opcode = JAL;
            inst.rd = rd as u8;
            inst.rs1 = rs1 as u8;
            inst.imm = mul32(imm, 2);
        }
        RV32::BR { bop, rs1, rs2, imm } => {
            inst.opcode = Opcode::from_u8((BEQ as u8) + (bop as u8)).unwrap();
            inst.rs1 = rs1 as u8;
            inst.rs2 = rs2 as u8;
            inst.imm = mul32(imm, 2);
        }
        RV32::LOAD { lop, rd, rs1, imm } => {
            inst.opcode = Opcode::from_u8((LB as u8) + (lop as u8)).unwrap();
            inst.rd = rd as u8;
            inst.rs1 = rs1 as u8;
            inst.imm = imm;
        }
        RV32::STORE { sop, rs1, rs2, imm } => {
            inst.opcode = Opcode::from_u8((SB as u8) + (sop as u8)).unwrap();
            inst.rs1 = rs1 as u8;
            inst.rs2 = rs2 as u8;
            inst.imm = imm;
        }
        RV32::ALUI { aop, rd, rs1, imm } => {
            inst.opcode = Opcode::from_u8((ADD as u8) + (aop as u8)).unwrap();
            inst.rd = rd as u8;
            inst.rs1 = rs1 as u8;
            inst.imm = imm;
        }
        RV32::ALU { aop, rd, rs1, rs2 } => {
            inst.opcode = Opcode::from_u8((ADD as u8) + (aop as u8)).unwrap();
            inst.rd = rd as u8;
            inst.rs1 = rs1 as u8;
            inst.rs2 = rs2 as u8;
        }
        RV32::ECALL => {
            inst.opcode = SYS;
        }
        RV32::FENCE | RV32::EBREAK => {
            inst.opcode = NOP;
        }
        RV32::UNIMP => {
            inst.opcode = HALT;
        }
    }
    inst
}

// Translate a code segment from RV32 to NVM. The result
// is a vector of NVM encoded instructions.

fn translate(pc: u32, bytes: &[u8]) -> Result<Vec<u64>> {
    let end = pc + bytes.len() as u32;
    let insts = parse_buf(pc, bytes)?;
    let mut output: Vec<u64> = Vec::with_capacity(insts.len());
    for i in insts {
        output.push(translate_inst(pc, end, i).into());
    }
    Ok(output)
}

/// Translate a RiscV ELF file to NVM.

// Note: no result is constructed at this point.

pub fn translate_elf(path: &Path) -> Result<()> {
    let file_data = read(path)?;
    let bytes = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes).unwrap();

    let segments: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    if segments.len() != 2 {
        panic!("ELF format: expected 2 loadable segments");
    }
    let code = segments[0];
    let data = segments[1];

    if code.p_flags & PF_X != PF_X {
        panic!("ELF format: expecting one code segment in low memory");
    }

    if data.p_flags & PF_X != 0 {
        panic!("ELF format: expecting one code segment in low memory");
    }

    println!("Code {code:?}");
    println!("Data {data:?}");

    let s = code.p_offset as usize;
    let e = (code.p_offset + code.p_filesz) as usize;

    translate(s as u32, &bytes[s..e]).unwrap();

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use nexus_riscv::rv32::{BOP, LOP, SOP, AOP};

    // these tests check that the invariants assumed by translate
    // are satisfied: the try_from's will never fail.
    macro_rules! inv {
        ($base:ident, $enum:ident, $op:ident) => {
            assert_eq!(
                Opcode::from_u8(($base as u8) + ($enum::$op as u8)).unwrap(),
                $op
            );
        };
    }

    #[test]
    fn check_bop_invariants() {
        inv!(BEQ, BOP, BEQ);
        inv!(BEQ, BOP, BNE);
        inv!(BEQ, BOP, BLT);
        inv!(BEQ, BOP, BGE);
        inv!(BEQ, BOP, BLTU);
        inv!(BEQ, BOP, BGEU);
    }

    #[test]
    fn check_lop_invariants() {
        inv!(LB, LOP, LB);
        inv!(LB, LOP, LH);
        inv!(LB, LOP, LW);
        inv!(LB, LOP, LBU);
        inv!(LB, LOP, LHU);
    }

    #[test]
    fn check_sop_invariants() {
        inv!(SB, SOP, SB);
        inv!(SB, SOP, SH);
        inv!(SB, SOP, SW);
    }

    #[test]
    fn check_aop_invariants() {
        inv!(ADD, AOP, ADD);
        inv!(ADD, AOP, SUB);
        inv!(ADD, AOP, SLL);
        inv!(ADD, AOP, SLT);
        inv!(ADD, AOP, SLTU);
        inv!(ADD, AOP, XOR);
        inv!(ADD, AOP, SRL);
        inv!(ADD, AOP, SRA);
        inv!(ADD, AOP, OR);
        inv!(ADD, AOP, AND);
    }
}
