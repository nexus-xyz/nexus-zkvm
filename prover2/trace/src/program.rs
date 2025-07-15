use nexus_common::cpu::Registers;
use nexus_vm::{
    cpu::RegisterFile,
    riscv::{BuiltinOpcode, InstructionType, Register},
    trace::{Block, Step},
    SyscallCode, WORD_SIZE,
};

use super::utils;

/// Program execution step.
#[derive(Clone, Copy, Debug)]
pub struct ProgramStep<'a> {
    /// Machine registers.
    pub regs: &'a RegisterFile,
    /// Program step.
    pub step: &'a Step,
}

impl<'a> From<&'a Block> for ProgramStep<'a> {
    fn from(block: &'a Block) -> Self {
        assert_eq!(block.steps.len(), 1, "k must be equal to 1");
        Self {
            regs: &block.regs,
            step: &block.steps[0],
        }
    }
}

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order
pub type Word = [u8; WORD_SIZE];
/// Represents a 32-bit word as 4 1-bit limbs in little-endian order
/// It is used for carry/borrow bits.
pub type BoolWord = [bool; WORD_SIZE];

/// Represents a 32-bit word as 4 8-bit limbs in little-endian order,
/// along with the count of effective bits.
pub type WordWithEffectiveBits = (Word, usize);

impl ProgramStep<'_> {
    /// Returns the value of the first operand (rd or rs1) as bytes.
    /// Always a register value in range u32.
    pub fn get_value_a(&self) -> Word {
        self.regs.read(self.step.instruction.op_a).to_le_bytes()
    }

    /// Returns the value of the destination register (rd) after execution.
    /// For instructions that don't write to rd, returns the original value.
    pub fn get_reg3_result_value(&self) -> Word {
        if let Some(syscall_code) = self.get_syscall_code() {
            if Self::syscall_accessed_reg3(syscall_code) {
                return self.get_result().expect("syscall must have a result");
            } else {
                return self.get_value_a();
            }
        }

        let instr = &self.step.instruction;
        if matches!(
            instr.ins_type,
            InstructionType::SType | InstructionType::BType
        ) {
            self.get_value_a()
        } else {
            self.get_result().expect("instruction must have a result")
        }
    }

    pub fn syscall_accessed_reg3(syscall_code: u32) -> bool {
        syscall_code == SyscallCode::ReadFromPrivateInput as u32
            || syscall_code == SyscallCode::OverwriteStackPointer as u32
            || syscall_code == SyscallCode::OverwriteHeapPointer as u32
    }

    /// Returns the value of the second operand (rs1 or rs2) as bytes.
    /// Always a register value in range u32.
    pub fn get_value_b(&self) -> Word {
        let value_b = if let Some(syscall_code) = self.get_syscall_code() {
            syscall_code
        } else {
            self.regs.read(self.step.instruction.op_b)
        };

        value_b.to_le_bytes()
    }

    /// Returns the first read register if no register gets accessed, zero
    pub fn get_op_b(&self) -> Register {
        if self.get_syscall_code().is_some() {
            Register::X17
        } else {
            self.step.instruction.op_b
        }
    }

    /// Returns the value of the third operand (rs2 or immediate) as bytes.
    /// The size of effective bits varies based on the instruction type.
    pub fn get_value_c(&self) -> WordWithEffectiveBits {
        let instruction = &self.step.instruction;
        let (value, effective_bits) = match instruction.ins_type {
            InstructionType::RType => (self.regs.read(Register::from(instruction.op_c as u8)), 32),
            InstructionType::IType | InstructionType::BType | InstructionType::SType => {
                (instruction.op_c, 12)
            }
            InstructionType::ITypeShamt => (instruction.op_c, 5),
            InstructionType::JType | InstructionType::UType => (instruction.op_c, 20),
            InstructionType::Unimpl => (0, 0),
        };

        (value.to_le_bytes(), effective_bits)
    }

    /// Returns the result computed in VM for cross-checking.
    pub fn get_result(&self) -> Option<Word> {
        self.step.result.map(|r| r.to_le_bytes())
    }

    pub fn get_op_a(&self) -> Register {
        // Special cases: ECALL and EBREAK OpA depend on syscall number
        if let Some(syscall_value) = self.get_syscall_code() {
            let syscall_number = SyscallCode::from(syscall_value);
            match syscall_number {
                SyscallCode::ReadFromPrivateInput | SyscallCode::OverwriteHeapPointer => {
                    Register::X10
                }
                SyscallCode::OverwriteStackPointer => Register::X2,
                _ => Register::X0,
            }
        } else {
            self.step.instruction.op_a
        }
    }

    /// Returns op-c, which may be either a register index (reg2-addr) or an immediate value.
    pub fn get_op_c(&self) -> u32 {
        let op_c_raw = self.step.instruction.op_c;
        match self.step.instruction.ins_type {
            InstructionType::RType => op_c_raw,
            InstructionType::BType | InstructionType::JType => {
                let (_, op_c_bits) = self.get_value_c();
                // immediate sign is part of instruction word and is used for decoding constraints.
                // op_c_sign_extended
                utils::sign_extend(op_c_raw, op_c_bits)
            }
            InstructionType::IType
            | InstructionType::SType
            | InstructionType::ITypeShamt
            | InstructionType::UType => {
                let (_, op_c_bits) = self.get_value_c();
                // op_c_zero_extended
                op_c_raw & ((1u32 << op_c_bits) - 1)
            }
            InstructionType::Unimpl => {
                panic!("Unimpl instruction doesn't have op_c: {:?}", self.step);
            }
        }
    }

    /// Returns true if the valueA register is x0 register.
    pub fn value_a_effective_flag(&self) -> bool {
        self.get_op_a() != Register::X0
    }

    /// Returns the signed bit of ValueA
    pub fn get_sgn_a(&self) -> bool {
        let a = self.get_value_a();
        (a[WORD_SIZE - 1] >> 7) == 1
    }

    /// Returns the signed bit of ValueB
    pub fn get_sgn_b(&self) -> bool {
        let b = self.get_value_b();
        (b[WORD_SIZE - 1] >> 7) == 1
    }

    /// Returns the signed bit of ValueC
    pub fn get_sgn_c(&self) -> bool {
        let c = self.get_value_c().0;
        (c[WORD_SIZE - 1] >> 7) == 1
    }

    /// Returns the syscall code value at register X17
    pub fn get_syscall_code(&self) -> Option<u32> {
        // Make sure the current instruction is ECALL, otherwise it's None
        match self.step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK) => {
                Some(self.regs.read(Register::X17))
            }
            _ => None,
        }
    }

    /// Returns true if the opcode is built-in.
    pub fn is_builtin(&self) -> bool {
        self.step.instruction.opcode.is_builtin()
    }
}
