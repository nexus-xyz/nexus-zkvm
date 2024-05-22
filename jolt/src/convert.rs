//! Conversion between NexusVM and Jolt types.

use nexus_riscv::rv32::{Inst, RV32};

use jolt_common::rv_trace as jolt_rv;

pub fn inst(inst: Inst) -> jolt_rv::ELFInstruction {
    jolt_rv::ELFInstruction {
        address: inst.pc as u64,
        opcode: rv32_opcode(inst.inst),
        rs1: inst.inst.rs1().map(Into::into),
        rs2: inst.inst.rs2().map(Into::into),
        rd: inst.inst.rd().map(Into::into),
        imm: inst.inst.imm(),
        // unsupported
        virtual_sequence_index: None,
    }
}

pub fn rv32_opcode(inst: RV32) -> jolt_rv::RV32IM {
    use jolt_rv::RV32IM as JoltRV32IM;
    use nexus_riscv::rv32::{AOP::*, BOP::*, LOP::*, RV32::*, SOP::*};

    match inst {
        LUI { .. } => JoltRV32IM::LUI,
        AUIPC { .. } => JoltRV32IM::AUIPC,
        JAL { .. } => JoltRV32IM::JAL,
        JALR { .. } => JoltRV32IM::JALR,

        BR { bop: BEQ, .. } => JoltRV32IM::BEQ,
        BR { bop: BNE, .. } => JoltRV32IM::BNE,
        BR { bop: BLT, .. } => JoltRV32IM::BLT,
        BR { bop: BGE, .. } => JoltRV32IM::BGE,
        BR { bop: BLTU, .. } => JoltRV32IM::BLTU,
        BR { bop: BGEU, .. } => JoltRV32IM::BGEU,

        LOAD { lop: LB, .. } => JoltRV32IM::LB,
        LOAD { lop: LH, .. } => JoltRV32IM::LH,
        LOAD { lop: LW, .. } => JoltRV32IM::LW,
        LOAD { lop: LBU, .. } => JoltRV32IM::LBU,
        LOAD { lop: LHU, .. } => JoltRV32IM::LHU,

        STORE { sop: SB, .. } => JoltRV32IM::SB,
        STORE { sop: SH, .. } => JoltRV32IM::SH,
        STORE { sop: SW, .. } => JoltRV32IM::SW,

        ALUI { aop: ADD, .. } => JoltRV32IM::ADDI,
        ALUI { aop: SUB, .. } => JoltRV32IM::ADDI, // note: does not exist
        ALUI { aop: SLL, .. } => JoltRV32IM::SLLI,
        ALUI { aop: SLT, .. } => JoltRV32IM::SLTI,
        ALUI { aop: SLTU, .. } => JoltRV32IM::SLTIU,
        ALUI { aop: XOR, .. } => JoltRV32IM::XORI,
        ALUI { aop: SRL, .. } => JoltRV32IM::SRLI,
        ALUI { aop: SRA, .. } => JoltRV32IM::SRAI,
        ALUI { aop: OR, .. } => JoltRV32IM::ORI,
        ALUI { aop: AND, .. } => JoltRV32IM::ANDI,

        ALU { aop: ADD, .. } => JoltRV32IM::ADD,
        ALU { aop: SUB, .. } => JoltRV32IM::SUB,
        ALU { aop: SLL, .. } => JoltRV32IM::SLL,
        ALU { aop: SLT, .. } => JoltRV32IM::SLT,
        ALU { aop: SLTU, .. } => JoltRV32IM::SLTU,
        ALU { aop: XOR, .. } => JoltRV32IM::XOR,
        ALU { aop: SRL, .. } => JoltRV32IM::SRL,
        ALU { aop: SRA, .. } => JoltRV32IM::SRA,
        ALU { aop: OR, .. } => JoltRV32IM::OR,
        ALU { aop: AND, .. } => JoltRV32IM::AND,

        FENCE => JoltRV32IM::FENCE,
        ECALL => JoltRV32IM::ECALL,
        EBREAK => JoltRV32IM::EBREAK,
        UNIMP => JoltRV32IM::UNIMPL,
    }
}
