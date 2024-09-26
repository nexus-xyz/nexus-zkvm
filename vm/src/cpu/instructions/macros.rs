macro_rules! implement_arithmetic_executor {
    ($name:ident, $operation:expr) => {
        impl InstructionState for $name {
            type Result = Option<()>;

            fn execute(&mut self) {
                #[allow(clippy::redundant_closure_call)]
                {
                    self.rd.1 = $operation(self.rs1, self.rs2);
                }
            }

            fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<Self::Result> {
                Ok(None)
            }

            fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<Self::Result> {
                Ok(None)
            }

            fn write_back(&self, cpu: &mut Cpu) {
                cpu.registers.write(self.rd.0, self.rd.1);
            }
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
                Self {
                    rd: (ins.op_a, registers[ins.op_a]),
                    rs1: registers[ins.op_b],
                    rs2: match ins.ins_type {
                        InstructionType::RType => registers[Register::from(ins.op_c as u8)],
                        _ => ins.op_c,
                    },
                }
            }
        }
    };
}

macro_rules! implement_store_instruction {
    ($name:ident, $size:expr) => {
        impl InstructionState for $name {
            type Result = Option<u32>;

            fn memory_read(&mut self, _: &impl MemoryProcessor) -> Result<Self::Result> {
                Ok(None)
            }

            fn memory_write(&self, memory: &mut impl MemoryProcessor) -> Result<Self::Result> {
                let address = self
                    .rs1
                    .checked_add(self.imm)
                    .ok_or(VMError::AddressCalculationOverflow)?;
                let value = memory.write(address, $size, self.rd)?;
                Ok(Some(value))
            }

            fn execute(&mut self) {}

            fn write_back(&self, _: &mut Cpu) {}
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
                Self {
                    rd: registers[ins.op_a],
                    rs1: registers[ins.op_b],
                    imm: ins.op_c,
                }
            }
        }
    };
}

macro_rules! implement_load_instruction {
    ($name:ident, $size:expr, $sign_extend:expr, $result_type:ty) => {
        impl InstructionState for $name {
            type Result = $result_type;

            fn memory_read(&mut self, memory: &impl MemoryProcessor) -> Result<Self::Result> {
                let address = self
                    .rs1
                    .checked_add(self.imm)
                    .ok_or(VMError::AddressCalculationOverflow)?;
                let value = memory.read(address, $size)?;

                self.rd.1 = if $sign_extend {
                    match $size {
                        MemAccessSize::Byte => ((value as i8) as i32) as u32,
                        MemAccessSize::HalfWord => ((value as i16) as i32) as u32,
                        MemAccessSize::Word => value,
                    }
                } else {
                    value
                };

                Ok(self.rd.1 as $result_type)
            }

            fn memory_write(&self, _: &mut impl MemoryProcessor) -> Result<Self::Result> {
                Ok(0 as $result_type)
            }

            fn execute(&mut self) {}

            fn write_back(&self, cpu: &mut Cpu) {
                cpu.registers.write(self.rd.0, self.rd.1);
            }
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &RegisterFile) -> Self {
                Self {
                    rd: (ins.op_a, registers[ins.op_a]),
                    rs1: registers[ins.op_b],
                    imm: ins.op_c,
                }
            }
        }
    };
}

pub(crate) use implement_arithmetic_executor;
pub(crate) use implement_load_instruction;
pub(crate) use implement_store_instruction;
