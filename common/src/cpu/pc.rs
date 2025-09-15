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
        self.value = self.value.wrapping_add(sign_extension_branch(imm));
    }

    // Jump and Link: Add immediate value to PC
    pub fn jal(&mut self, imm: u32) {
        self.value = self.value.wrapping_add(sign_extension_jal(imm));
    }

    // Jump and Link Register: Set PC to rs1 + imm
    pub fn jalr(&mut self, rs1: u32, imm: u32) {
        // RISC-V spec: JALR clears bit 0 of the target address (enforce 2-byte alignment)
        self.value = rs1.wrapping_add(sign_extension_jalr(imm)) & !1u32;
    }
}

impl PartialEq<u32> for PC {
    fn eq(&self, other: &u32) -> bool {
        self.value == *other
    }
}

#[inline]
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
#[inline]
const fn sign_extension_branch(imm: u32) -> u32 {
    sign_extension(imm, 13)
}

// Sign extension for JAL (21-bit immediate)
#[inline]
const fn sign_extension_jal(imm: u32) -> u32 {
    sign_extension(imm, 21)
}

// Sign extension for JALR (12-bit immediate)
#[inline]
const fn sign_extension_jalr(imm: u32) -> u32 {
    sign_extension(imm, 12)
}
