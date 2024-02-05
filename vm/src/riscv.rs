//! Translation of RISC-V ro NexusVM.

use std::path::Path;
use std::fs::read;
use num_traits::FromPrimitive;

use elf::{
    abi::{PT_LOAD, PF_X},
    endian::LittleEndian,
    segment::ProgramHeader,
    ElfBytes,
};

use nexus_riscv::{
    nop_vm, loop_vm, VMError,
    machines::lookup_test_machine,
    vm::eval::VM,
    rv32::{RV32, Inst as RVInst, parse::parse_inst},
};
pub use nexus_riscv::VMOpts;

use crate::error::{Result, NexusVMError::ELFFormat};
use crate::instructions::{Inst, Opcode, Opcode::*, Width::BU};
use crate::eval::NexusVM;

#[inline]
fn add32(a: u32, b: u32) -> u32 {
    a.overflowing_add(b).0
}

#[inline]
fn mul32(a: u32, b: u32) -> u32 {
    a.overflowing_mul(b).0
}

// Translate a RV32 instruction to an NexusVM instruction.
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

    let npc = start + (pc - start) * 2;

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
                inst.imm = add32(npc, mul32(imm, 2));
            } else {
                inst.imm = res;
            }
        }
        RV32::JAL { rd, imm } => {
            inst.opcode = JAL;
            inst.rd = rd as u8;
            inst.imm = add32(npc, mul32(imm, 2));
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

/// Translate a RiscV ELF file to NexusVM.
pub fn translate_elf(path: &Path) -> Result<NexusVM> {
    let file_data = read(path)?;
    let bytes = file_data.as_slice();
    translate_elf_bytes(bytes)
}

/// Translate a RiscV ELF file to NexusVM.
#[allow(clippy::needless_range_loop)]
pub fn translate_elf_bytes(bytes: &[u8]) -> Result<NexusVM> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;

    if file.ehdr.e_entry != 0x1000 {
        return Err(ELFFormat("invalid start address"));
    }

    let segments: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .collect();

    if segments.len() != 2 {
        return Err(ELFFormat("expected 2 loadable segments"));
    }
    let code = segments[0];
    let data = segments[1];

    if code.p_flags & PF_X != PF_X {
        return Err(ELFFormat("expecting one code segment in low memory"));
    }

    if data.p_flags & PF_X != 0 {
        return Err(ELFFormat("expecting one data segment in high memory"));
    }

    if code.p_offset + code.p_filesz * 2 >= data.p_offset {
        return Err(ELFFormat("not enough room to expand code to NexusVM"));
    }

    let mut vm = NexusVM::default();
    vm.pc = 0x1000;

    // write code segment
    let s = code.p_offset as u32;
    let e = (code.p_offset + code.p_filesz) as u32;
    for i in s..e {
        let inst = parse_inst(i, &bytes[i as usize..])?;
        let pc = s + (i - s) * 2;
        let inst = translate_inst(s, e, inst);
        vm.memory.write_inst(pc, inst.into())?;
    }

    // write data segment
    let s = data.p_offset as usize;
    let e = (data.p_offset + data.p_filesz) as usize;
    for i in s..e {
        let b = bytes[i];
        vm.memory.store(BU, (s + i) as u32, b as u32)?;
    }

    Ok(vm)
}

// internal function to translate RISC-V test VMs to NexusVMs
fn translate_test_machine(rvm: &VM) -> Result<NexusVM> {
    let mut nvm = NexusVM::default();
    nvm.pc = rvm.regs.pc;
    let mut i = 0;
    loop {
        let rpc = nvm.pc + i * 4;
        let slice = rvm.mem.rd_page(rpc);
        let inst = match parse_inst(rpc, slice) {
            Err(_) => break,
            Ok(inst) => inst,
        };

        let inst = translate_inst(nvm.pc, nvm.pc + 0x1000, inst);
        let dword = u64::from(inst);
        let npc = nvm.pc + i * 8;
        nvm.memory.write_inst(npc, dword)?;

        i += 1;
    }
    Ok(nvm)
}

/// Load a NexusVM according the `opts`.
pub fn load_nvm(opts: &VMOpts) -> Result<NexusVM> {
    if let Some(k) = opts.nop {
        translate_test_machine(&nop_vm(k))
    } else if let Some(k) = opts.loopk {
        translate_test_machine(&loop_vm(k))
    } else if let Some(m) = &opts.machine {
        if let Some(vm) = lookup_test_machine(m) {
            translate_test_machine(&vm)
        } else {
            Err(VMError::UnknownMachine(m.clone()).into())
        }
    } else {
        translate_elf(opts.file.as_ref().unwrap())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::eval::eval;
    use nexus_riscv::rv32::{BOP, LOP, SOP, AOP};
    use nexus_riscv::machines::MACHINES;

    // this function is used by other test crates
    pub fn test_machines() -> Vec<(&'static str, NexusVM)> {
        MACHINES
            .iter()
            .map(|(name, f_vm, _)| {
                let rvm = f_vm();
                let nvm = translate_test_machine(&rvm).unwrap();
                (*name, nvm)
            })
            .collect()
    }

    #[test]
    fn compare_test_machines() {
        let tests = MACHINES.iter().zip(test_machines());
        for ((name, _, f_regs), (_, mut nvm)) in tests {
            println!("Checking machine {name}");
            let regs = f_regs();

            eval(&mut nvm, false).unwrap();

            let npc = 0x1000 + (regs.pc - 0x1000) * 2;
            assert_eq!(nvm.pc, npc);

            // code addresses will not match, so register checks
            // for tests with jal are skipped
            if name != &"loop10" && name != &"jump" {
                assert_eq!(nvm.regs, regs.x);
            }
        }
    }

    // these tests check that the invariants assumed by translate
    // are satisfied: the from_u8's will never fail.
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
