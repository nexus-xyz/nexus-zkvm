#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PC {
    pub value: u32,
}

impl PC {
    // Increment PC by 4 bytes (standard instruction length)
    pub fn step(&mut self) {
        self.value = self.value.wrapping_add(4);
    }

    // Branch: Add immediate value to PC
    pub fn branch(&mut self, imm: u32) {
        self.value = self.value.wrapping_add(sign_extension_branch(imm) as i32 as u32);
    }

    // Jump and Link: Add immediate value to PC
    pub fn jal(&mut self, imm: u32) {
        self.value = self.value.wrapping_add(sign_extension_jal(imm) as i32 as u32);
    }

    // Jump and Link Register: Set PC to rs1 + imm
    pub fn jalr(&mut self, rs1: u32, imm: u32) {
        self.value = rs1.wrapping_add(sign_extension_jalr(imm) as i32 as u32);
    }
}

impl PartialEq<u32> for PC {
    fn eq(&self, other: &u32) -> bool {
        self.value == *other
    }
}

#[inline]
const fn sign_extension(imm: u32, bits: u32) -> i32 {
    let mask = 1u32 << (bits - 1);
    let value = imm & ((1u32 << bits) - 1); // Ensure we only use the specified number of bits
    if value & mask != 0 {
        // If the sign bit is set, extend with 1s (negative value)
        (value as i32) | (!((1u32 << bits) - 1) as i32)
    } else {
        value as i32
    }
}

// Sign extension for Branch (13-bit immediate)
#[inline]
const fn sign_extension_branch(imm: u32) -> i32 {
    sign_extension(imm, 13)
}

// Sign extension for JAL (21-bit immediate)
#[inline]
const fn sign_extension_jal(imm: u32) -> i32 {
    sign_extension(imm, 21)
}

// Sign extension for JALR (12-bit immediate)
#[inline]
const fn sign_extension_jalr(imm: u32) -> i32 {
    sign_extension(imm, 12)
}
