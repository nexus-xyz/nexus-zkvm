macro_rules! implement_arithmetic_executor {
    ($name:ident, $operation:expr) => {
        impl InstructionState for $name {
            fn execute(&mut self) {
                #[allow(clippy::redundant_closure_call)]
                {
                    self.rd.1 = $operation(self.rs1, self.rs2);
                }
            }

            fn memory_read(
                &mut self,
                _: &impl MemoryProcessor,
            ) -> Result<LoadOps, nexus_common::error::MemoryError> {
                <$name as InstructionState>::readless()
            }

            fn memory_write(
                &self,
                _: &mut impl MemoryProcessor,
            ) -> Result<StoreOps, nexus_common::error::MemoryError> {
                <$name as InstructionState>::writeless()
            }

            fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
                cpu.registers_mut().write(self.rd.0, self.rd.1);
                Some(self.rd.1)
            }
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
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
            fn memory_read(
                &mut self,
                _: &impl MemoryProcessor,
            ) -> Result<LoadOps, nexus_common::error::MemoryError> {
                <$name as InstructionState>::readless()
            }

            fn memory_write(
                &self,
                memory: &mut impl MemoryProcessor,
            ) -> Result<StoreOps, nexus_common::error::MemoryError> {
                let address = if (self.imm as i32) < 0 {
                    self.rs1
                        .checked_sub((self.imm as i32).abs() as u32)
                        .ok_or(nexus_common::error::MemoryError::AddressCalculationUnderflow)?
                } else {
                    self.rs1
                        .checked_add(self.imm as u32)
                        .ok_or(nexus_common::error::MemoryError::AddressCalculationOverflow)?
                };
                Ok(memory.write(address, $size, self.rd)?.into())
            }

            fn execute(&mut self) {}

            fn write_back(&self, _: &mut impl Processor) -> Option<u32> {
                None
            }
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
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
            fn memory_read(
                &mut self,
                memory: &impl MemoryProcessor,
            ) -> Result<LoadOps, nexus_common::error::MemoryError> {
                let address = if (self.imm as i32) < 0 {
                    self.rs1
                        .checked_sub((self.imm as i32).abs() as u32)
                        .ok_or(nexus_common::error::MemoryError::AddressCalculationUnderflow)?
                } else {
                    self.rs1
                        .checked_add(self.imm as u32)
                        .ok_or(nexus_common::error::MemoryError::AddressCalculationOverflow)?
                };
                let op = memory.read(address, $size)?;
                let LoadOp::Op(_, _, value) = op;

                self.rd.1 = if $sign_extend {
                    match $size {
                        MemAccessSize::Byte => ((value as i8) as i32) as u32,
                        MemAccessSize::HalfWord => ((value as i16) as i32) as u32,
                        MemAccessSize::Word => value,
                    }
                } else {
                    value
                };

                Ok(op.into())
            }

            fn memory_write(
                &self,
                _: &mut impl nexus_common::memory::MemoryProcessor,
            ) -> Result<StoreOps, nexus_common::error::MemoryError> {
                <$name as InstructionState>::writeless()
            }

            fn execute(&mut self) {}

            fn write_back(&self, cpu: &mut impl Processor) -> Option<u32> {
                cpu.registers_mut().write(self.rd.0, self.rd.1);
                Some(self.rd.1)
            }
        }

        impl InstructionExecutor for $name {
            type InstructionState = Self;

            fn decode(ins: &Instruction, registers: &impl Registers) -> Self {
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
