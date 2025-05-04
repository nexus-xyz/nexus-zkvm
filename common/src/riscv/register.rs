use serde::{Deserialize, Serialize};
use std::fmt::Display;

pub const NUM_REGISTERS: usize = 32;

/// A register stores a 32-bit value used by operations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Register {
    #[default]
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    X31 = 31,
}

impl From<u8> for Register {
    fn from(value: u8) -> Self {
        match value {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29,
            30 => Register::X30,
            31 => Register::X31,
            _ => unreachable!(),
        }
    }
}

impl Register {
    pub fn abi_name(&self) -> &'static str {
        match self {
            Register::X0 => "zero", // Hardwired zero
            Register::X1 => "ra",   // Return address
            Register::X2 => "sp",   // Stack pointer
            Register::X3 => "gp",   // Global pointer
            Register::X4 => "tp",   // Thread pointer
            Register::X5 => "t0",   // Temporary/alternate link register
            Register::X6 => "t1",   // Temporary register 1
            Register::X7 => "t2",   // Temporary register 2
            Register::X8 => "s0",   // Saved register 0 / Frame pointer
            Register::X9 => "s1",   // Saved register 1
            Register::X10 => "a0",  // Function argument 0 / Return value 0
            Register::X11 => "a1",  // Function argument 1 / Return value 1
            Register::X12 => "a2",  // Function argument 2
            Register::X13 => "a3",  // Function argument 3
            Register::X14 => "a4",  // Function argument 4
            Register::X15 => "a5",  // Function argument 5
            Register::X16 => "a6",  // Function argument 6
            Register::X17 => "a7",  // Function argument 7
            Register::X18 => "s2",  // Saved register 2
            Register::X19 => "s3",  // Saved register 3
            Register::X20 => "s4",  // Saved register 4
            Register::X21 => "s5",  // Saved register 5
            Register::X22 => "s6",  // Saved register 6
            Register::X23 => "s7",  // Saved register 7
            Register::X24 => "s8",  // Saved register 8
            Register::X25 => "s9",  // Saved register 9
            Register::X26 => "s10", // Saved register 10
            Register::X27 => "s11", // Saved register 11
            Register::X28 => "t3",  // Temporary register 3
            Register::X29 => "t4",  // Temporary register 4
            Register::X30 => "t5",  // Temporary register 5
            Register::X31 => "t6",  // Temporary register 6
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Register::X0 => "x0",   // Hardwired zero
            Register::X1 => "x1",   // Return address
            Register::X2 => "x2",   // Stack pointer
            Register::X3 => "x3",   // Global pointer
            Register::X4 => "x4",   // Thread pointer
            Register::X5 => "x5",   // Temporary/alternate link register
            Register::X6 => "x6",   // Temporary register 1
            Register::X7 => "x7",   // Temporary register 2
            Register::X8 => "x8",   // Saved register 0 / Frame pointer
            Register::X9 => "x9",   // Saved register 1
            Register::X10 => "x10", // Function argument 0 / Return value 0
            Register::X11 => "x11", // Function argument 1 / Return value 1
            Register::X12 => "x12", // Function argument 2
            Register::X13 => "x13", // Function argument 3
            Register::X14 => "x14", // Function argument 4
            Register::X15 => "x15", // Function argument 5
            Register::X16 => "x16", // Function argument 6
            Register::X17 => "x17", // Function argument 7
            Register::X18 => "x18", // Saved register 2
            Register::X19 => "x19", // Saved register 3
            Register::X20 => "x20", // Saved register 4
            Register::X21 => "x21", // Saved register 5
            Register::X22 => "x22", // Saved register 6
            Register::X23 => "x23", // Saved register 7
            Register::X24 => "x24", // Saved register 8
            Register::X25 => "x25", // Saved register 9
            Register::X26 => "x26", // Saved register 10
            Register::X27 => "x27", // Saved register 11
            Register::X28 => "x28", // Temporary register 3
            Register::X29 => "x29", // Temporary register 4
            Register::X30 => "x30", // Temporary register 5
            Register::X31 => "x31", // Temporary register 6
        }
    }
}

impl Display for Register {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.abi_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_from_u32() {
        for i in 0..32 {
            let reg = Register::from(i);
            assert_eq!(reg as u8, i);
        }
    }

    #[test]
    fn test_register_abi_name() {
        let abi_names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
            "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        ];

        for i in 0..32 {
            let reg = Register::from(i);
            assert_eq!(
                reg.abi_name(),
                abi_names[i as usize],
                "Mismatch for register X{i}"
            );
        }
    }

    #[test]
    fn test_register_display() {
        for i in 0..32 {
            let reg = Register::from(i);
            assert_eq!(
                format!("{reg}"),
                reg.abi_name(),
                "Display mismatch for register X{}",
                i
            );
        }
    }
}
