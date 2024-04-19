//! Translation of RISC-V ro NexusVM.

use num_traits::FromPrimitive;
use std::fs::read;
use std::path::Path;
use std::time::Instant;

use elf::{
    abi::{PF_X, PT_LOAD},
    endian::LittleEndian,
    segment::ProgramHeader,
    ElfBytes,
};

use nexus_vm::{
    eval::NexusVM,
    instructions::{Inst, Opcode, Opcode::*, Width::BU},
    memory::Memory,
    trace::{trace, Trace},
};

use crate::{
    error::{Result, VMError::ELFFormat},
    machines::{lookup_test_code, loop_code, nop_code},
    rv32::{parse::parse_inst, Inst as RVInst, AOP, RV32},
    VMError, VMOpts,
};

#[inline]
fn add32(a: u32, b: u32) -> u32 {
    a.overflowing_add(b).0
}

#[inline]
fn mul32(a: u32, b: u32) -> u32 {
    a.overflowing_mul(b).0
}

// A simple, stable peephole optimizer for local constant propagation.

fn peephole(insn: &mut [RVInst]) {
    for i in 0..insn.len() {
        match const_prop(&insn[i..]) {
            None => (),
            Some(v) => {
                for (j, x) in v.iter().enumerate() {
                    insn[i + j] = *x;
                }
            }
        }
    }
}

// utility functions for contructing RV32 instructions.
// Note: the word field is invalid, but it is no longer used
// at this point.

fn rv32(pc: u32, inst: RV32) -> RVInst {
    RVInst { pc, len: 4, word: 0, inst }
}

fn nop(pc: u32) -> RVInst {
    rv32(pc, RV32::ALUI { aop: AOP::ADD, rd: 0, rs1: 0, imm: 0 })
}

fn jalr(pc: u32, rd: u32, rs1: u32, imm: u32) -> RVInst {
    rv32(pc, RV32::JALR { rd, rs1, imm })
}

fn const_prop(insn: &[RVInst]) -> Option<Vec<RVInst>> {
    match insn {
        [RVInst {
            pc: pc1,
            inst: RV32::AUIPC { rd: rd1, imm: imm1 },
            ..
        }, RVInst {
            pc: pc2,
            inst: RV32::JALR { rd: rd2, rs1, imm: imm2 },
            ..
        }, ..]
            if rd1 == rs1 =>
        {
            let target = add32(add32(*pc1, *imm1), *imm2);
            Some(vec![nop(*pc1), jalr(*pc2, *rd2, 0, target)])
        }
        _ => None,
    }
}

// Translate a RV32 instruction to an NexusVM instruction.
//
// Note: the from_u8's cannot fail if the test cases
// in this module all pass: the unwrap's are safe.
fn translate_inst(rv: RVInst) -> (u32, Inst) {
    let RVInst { pc, len: _, word: _, inst: rv } = rv;

    // Note, this is valid for programs compiled with nexus_rt,
    // but is not generally correct.
    let npc = pc * 2;

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
            inst.imm = add32(pc, imm);
        }
        RV32::JAL { rd, imm } => {
            inst.opcode = JAL;
            inst.rd = rd as u8;
            inst.imm = mul32(add32(pc, imm), 2);
        }
        RV32::JALR { rd, rs1, imm } => {
            inst.opcode = JAL;
            inst.rd = rd as u8;
            inst.rs1 = rs1 as u8;
            // call / return are treated differently to make translation
            // from RISC-V easy.
            if rs1 == 0 {
                inst.imm = mul32(imm, 2);
            } else {
                inst.imm = imm;
            }
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
            // Per the RISC-V spec, for an ecall `rd = 0` and the system determines
            // how to return a value, e.g. by modifying register `x10` (aka `a0`).
            //
            // For the NVM, we formalize this by setting `rd = 10` and having each
            // ecall modify `x10`, even if to just write zero. By doing so, we know
            // that `rd` points to the modified register, and so we will always
            // generate the R1CS circuit constraints correctly.
            inst.rd = 10;
        }
        RV32::FENCE | RV32::EBREAK => {
            inst.opcode = NOP;
        }
        RV32::UNIMP => {
            inst.opcode = HALT;
        }
    }
    (npc, inst)
}

/// Translate a RiscV ELF file to NexusVM.
pub fn translate_elf<M: Memory>(path: &Path) -> Result<NexusVM<M>> {
    let file_data = read(path)?;
    let bytes = file_data.as_slice();
    translate_elf_bytes(bytes)
}

/// Translate a RiscV ELF file to NexusVM.
pub fn translate_elf_bytes<M: Memory>(bytes: &[u8]) -> Result<NexusVM<M>> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;

    let segments: Vec<ProgramHeader> = file
        .segments()
        .unwrap()
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD && phdr.p_filesz > 0)
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

    if code.p_vaddr + code.p_filesz * 2 > data.p_vaddr {
        return Err(ELFFormat("not enough room to expand code to NexusVM"));
    }

    let mut vm = NexusVM::<M>::default();
    vm.pc = file.ehdr.e_entry as u32;

    // load code segment
    let mut rv_code: Vec<RVInst> = Vec::new();
    for i in (0..code.p_filesz).step_by(4) {
        let ndx = (code.p_offset + i) as usize;
        let pc = (code.p_vaddr + i) as u32;
        let inst = parse_inst(pc, &bytes[ndx..])?;
        rv_code.push(inst);
    }

    // perform basic constant-propigation to simplify
    // transformation to NVM
    peephole(&mut rv_code);

    // write code segment
    for inst1 in rv_code {
        let (pc, inst) = translate_inst(inst1);
        vm.memory.write_inst(pc, inst.into())?;
    }

    // write data segment
    for i in 0..data.p_filesz {
        let ndx = (data.p_offset + i) as usize;
        let addr = (data.p_vaddr + i) as u32;
        let b = bytes[ndx] as u32;
        vm.memory.store(BU, addr, b)?;
    }

    Ok(vm)
}

// internal function to translate RISC-V test VMs to NexusVMs
fn translate_test_machine<M: Memory>(rv_code: &[u32]) -> Result<NexusVM<M>> {
    let mut rv_code = rv_code
        .iter()
        .enumerate()
        .map(|(i, word)| parse_inst(i as u32 * 4, &word.to_le_bytes()).unwrap())
        .collect::<Vec<_>>();

    peephole(rv_code.as_mut_slice());

    let mut nvm = NexusVM::<M>::default();
    for inst in rv_code {
        let (pc, inst) = translate_inst(inst);
        nvm.memory.write_inst(pc, inst.into())?;
    }
    Ok(nvm)
}

/// Load as a NexusVM according the `opts`.
fn load_nvm<M: Memory>(opts: &VMOpts) -> Result<NexusVM<M>> {
    if let Some(k) = opts.nop {
        translate_test_machine(&nop_code(k))
    } else if let Some(k) = opts.loopk {
        translate_test_machine(&loop_code(k))
    } else if let Some(m) = &opts.machine {
        if let Some(vm) = lookup_test_code(m) {
            translate_test_machine(&vm)
        } else {
            Err(VMError::UnknownMachine(m.clone()))
        }
    } else {
        translate_elf(opts.file.as_ref().unwrap())
    }
}

fn estimate_size<M: Memory>(tr: &Trace<M::Proof>) -> usize {
    use std::mem::size_of_val as sizeof;
    sizeof(tr)
        + tr.blocks.len()
            * (sizeof(&tr.blocks[0]) + tr.blocks[0].steps.len() * sizeof(&tr.blocks[0].steps[0]))
}

/// Load and run as a NexusVM according to the `opts`.
pub fn run_as_nvm<M: Memory>(opts: &VMOpts, pow: bool, show: bool) -> Result<Trace<M::Proof>, VMError> {
    let mut vm = load_nvm::<M>(opts)?;

    if show {
        println!("Executing program...");
    }

    let start = Instant::now();
    let trace = trace::<M>(&mut vm, opts.k, pow)?;

    if show {
        println!(
            "Executed {} instructions in {:?}. {} bytes used by trace.",
            trace.k * trace.blocks.len(),
            start.elapsed(),
            estimate_size::<M>(&trace)
        );
    }

    Ok(trace)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::machines::MACHINES;
    use crate::rv32::{AOP, BOP, LOP, SOP};
    use nexus_vm::eval::eval;
    use nexus_vm::memory::trie::MerkleTrie;

    // Generate a list of NVM test machines
    pub fn test_machines() -> Vec<(&'static str, NexusVM<MerkleTrie>)> {
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

            assert_eq!(nvm.pc, regs.pc * 2);

            // code addresses will not match, so register checks
            // for jump tests are skipped
            if name != &"jump" {
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
