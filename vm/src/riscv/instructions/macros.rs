macro_rules! impl_r_type_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: RType) -> Self::InstructionResult {
                Instruction::from_r_type($opcode, dec_insn)
            }
        )+
    };
}

macro_rules! impl_i_type_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: IType) -> Self::InstructionResult {
                Instruction::from_i_type($opcode, dec_insn)
            }
        )+
    };
}

macro_rules! impl_systemcall_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self) -> Self::InstructionResult {
                Instruction::new(
                    $opcode,
                    Register::X0,
                    Register::X0,
                    0,
                    InstructionType::IType,
                )
            }
        )+
    };
}

macro_rules! impl_i_type_shamt_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
                Instruction::from_i_type_shamt($opcode, dec_insn)
            }
        )+
    };
}

macro_rules! impl_s_type_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: SType) -> Self::InstructionResult {
                Instruction::from_s_type($opcode, dec_insn)
            }
        )+
    };
}

macro_rules! impl_b_type_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: BType) -> Self::InstructionResult {
                Instruction::from_b_type($opcode, dec_insn)
            }
        )+
    };
}

macro_rules! impl_u_type_instructions {
    ($($name:ident => $opcode:expr),+ $(,)?) => {
        $(
            fn $name(&mut self, dec_insn: UType) -> Self::InstructionResult {
                Instruction::new(
                    $opcode,
                    Register::from(dec_insn.rd as u8),
                    Register::X0,
                    ((dec_insn.imm as u32) >> 12) as _,
                    InstructionType::UType,
                )
            }
        )+
    };
}

macro_rules! unimplemented_instructions {
    ($($name:ident($($arg:ident: $type:ty)?)),+ $(,)?) => {
        $(
            fn $name(&mut self$(, _: $type)?) -> Self::InstructionResult {
                Instruction::unimpl()
            }
        )+
    };
}

pub(crate) use impl_b_type_instructions;
pub(crate) use impl_i_type_instructions;
pub(crate) use impl_i_type_shamt_instructions;
pub(crate) use impl_r_type_instructions;
pub(crate) use impl_s_type_instructions;
pub(crate) use impl_systemcall_instructions;
pub(crate) use impl_u_type_instructions;
pub(crate) use unimplemented_instructions;
