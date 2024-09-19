use std::fmt::Display;
use std::ops::Index;

use crate::riscv::Register;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterFile {
    registers: [u32; 32],
}

impl RegisterFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, reg: Register) -> u32 {
        if reg == Register::X0 {
            0 // X0 is hardwired to zero
        } else {
            self.registers[reg as usize]
        }
    }

    pub fn write(&mut self, reg: Register, value: u32) {
        if reg != Register::X0 {
            self.registers[reg as usize] = value;
        }
    }
}

impl Index<Register> for RegisterFile {
    type Output = u32;

    fn index(&self, index: Register) -> &Self::Output {
        &self.registers[index as usize]
    }
}

impl Display for RegisterFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "+--------+------------+--------+------------+--------+------------+--------+------------+")?;
        writeln!(f, "| T Regs | Value      | A Regs | Value      | S Regs | Value      | Others | Value      |")?;
        writeln!(f, "+--------+------------+--------+------------+--------+------------+--------+------------+")?;

        let t_regs = [4, 5, 6, 7, 28, 29, 30, 31];
        let a_regs = [10, 11, 12, 13, 14, 15, 16, 17];
        let s_regs = [8, 9, 18, 19, 20, 21, 22, 23];
        let other_regs = [0, 1, 2, 3, 24, 25, 26, 27];

        let max_rows = t_regs
            .len()
            .max(a_regs.len())
            .max(s_regs.len())
            .max(other_regs.len());

        for i in 0..max_rows {
            let t_reg = t_regs
                .get(i)
                .map(|&r| (Register::from(r as u8), self.registers[r]));
            let a_reg = a_regs
                .get(i)
                .map(|&r| (Register::from(r as u8), self.registers[r]));
            let s_reg = s_regs
                .get(i)
                .map(|&r| (Register::from(r as u8), self.registers[r]));
            let other_reg = other_regs
                .get(i)
                .map(|&r| (Register::from(r as u8), self.registers[r]));

            writeln!(
                f,
                "| {:<6} | {:#010x} | {:<6} | {:#010x} | {:<6} | {:#010x} | {:<6} | {:#010x} |",
                t_reg.map_or("", |(r, _)| r.abi_name()),
                t_reg.map_or(0, |(_, v)| v),
                a_reg.map_or("", |(r, _)| r.abi_name()),
                a_reg.map_or(0, |(_, v)| v),
                s_reg.map_or("", |(r, _)| r.abi_name()),
                s_reg.map_or(0, |(_, v)| v),
                other_reg.map_or("", |(r, _)| r.abi_name()),
                other_reg.map_or(0, |(_, v)| v),
            )?;
        }

        writeln!(f, "+--------+------------+--------+------------+--------+------------+--------+------------+")?;
        Ok(())
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PC {
    pub value: u32,
}

const fn sign_extension(imm: u32, bits: u32) -> u32 {
    let mask = 1u32 << (bits - 1);
    let value = imm & ((1u32 << bits) - 1); // Ensure we only use the specified number of bits
    if value & mask != 0 {
        // If the sign bit is set, extend with 1s
        value | !((1u32 << bits) - 1)
    } else {
        // If the sign bit is not set, extend with 0s
        value
    }
}

// Sign extension for Branch (13-bit immediate)
const fn sign_extension_branch(imm: u32) -> u32 {
    sign_extension(imm, 13)
}

// Sign extension for JAL (21-bit immediate)
const fn sign_extension_jal(imm: u32) -> u32 {
    sign_extension(imm, 21)
}

// Sign extension for JALR (12-bit immediate)
const fn sign_extension_jalr(imm: u32) -> u32 {
    sign_extension(imm, 12)
}

impl PC {
    // Increment PC by 4 bytes (standard instruction length)
    pub fn step(&mut self) {
        self.value = self.value.wrapping_add(4);
    }

    // Branch: Add immediate value to PC
    pub fn branch(&mut self, imm: u32) {
        self.value = self.value.wrapping_add(sign_extension_branch(imm));
    }

    // Jump and Link: Add immediate value to PC
    pub fn jal(&mut self, imm: u32) {
        self.value = self.value.wrapping_add(sign_extension_jal(imm));
    }

    // Jump and Link Register: Set PC to rs1 + imm
    pub fn jalr(&mut self, rs1: u32, imm: u32) {
        self.value = rs1.wrapping_add(sign_extension_jalr(imm));
    }
}

impl PartialEq<u32> for PC {
    fn eq(&self, other: &u32) -> bool {
        self.value == *other
    }
}
