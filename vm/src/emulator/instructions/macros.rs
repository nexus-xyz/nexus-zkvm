macro_rules! define_execute_ALU_instruction {
    ($fn_name:ident, $instruction_type:ty) => {
        pub fn $fn_name(
            cpu: &mut Cpu,
            _data_memory: &mut Memory,
            instruction: &Instruction,
        ) -> Result<()> {
            let mut ins = <$instruction_type>::decode(instruction, &cpu.registers);
            ins.execute();
            ins.write_back(cpu);
            Ok(())
        }
    };
}

macro_rules! define_execute_STORE_instruction {
    ($fn_name:ident, $instruction_type:ty) => {
        pub fn $fn_name(
            cpu: &mut Cpu,
            data_memory: &mut Memory,
            instruction: &Instruction,
        ) -> Result<()> {
            let ins = <$instruction_type>::decode(instruction, &cpu.registers);
            ins.memory_write(data_memory)?;
            Ok(())
        }
    };
}

macro_rules! define_execute_LOAD_instruction {
    ($fn_name:ident, $instruction_type:ty) => {
        pub fn $fn_name(
            cpu: &mut Cpu,
            data_memory: &mut Memory,
            instruction: &Instruction,
        ) -> Result<()> {
            let mut ins = <$instruction_type>::decode(instruction, &cpu.registers);
            ins.memory_read(&data_memory)?;
            ins.write_back(cpu);
            Ok(())
        }
    };
}

macro_rules! define_execute_BRANCH_instruction {
    ($fn_name:ident, $instruction_type:ty) => {
        pub fn $fn_name(
            cpu: &mut Cpu,
            _data_memory: &mut Memory,
            instruction: &Instruction,
        ) -> Result<()> {
            let ins = <$instruction_type>::decode(instruction, &cpu.registers);
            ins.write_back(cpu);
            Ok(())
        }
    };
}
pub(crate) use define_execute_ALU_instruction;
pub(crate) use define_execute_BRANCH_instruction;
pub(crate) use define_execute_LOAD_instruction;
pub(crate) use define_execute_STORE_instruction;
