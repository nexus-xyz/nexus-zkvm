use std::fmt::Display;
use std::ops::Index;

use nexus_common::cpu::Registers;

use crate::riscv::Register;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterFile {
    registers: [u32; 32],
}

impl RegisterFile {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Registers for RegisterFile {
    fn read(&self, reg: Register) -> u32 {
        if reg == Register::X0 {
            0 // X0 is hardwired to zero
        } else {
            self.registers[reg as usize]
        }
    }

    fn write(&mut self, reg: Register, value: u32) {
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
