use std::{fmt::Display, ops::Index};

use crate::riscv::register::Register;

pub trait Registers: Index<Register, Output = u32> + Display {
    fn read(&self, reg: Register) -> u32;
    fn write(&mut self, reg: Register, value: u32);
}
