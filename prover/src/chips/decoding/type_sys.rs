use crate::{
    column::Column::{self, IsEbreak, IsEcall, OpB},
    components::MAX_LOOKUP_TUPLE_SIZE,
    traits::MachineChip,
    virtual_column::{IsTypeSys, VirtualColumn},
};

use crate::trace::eval::trace_eval;
use nexus_vm::{riscv::BuiltinOpcode, WORD_SIZE};
use stwo_prover::core::fields::m31::BaseField;

pub struct TypeSysChip;

impl MachineChip for TypeSysChip {
    fn fill_main_trace(
        traces: &mut crate::trace::TracesBuilder,
        row_idx: usize,
        vm_step: &Option<crate::trace::ProgramStep>, // None for padding
        _side_note: &mut crate::trace::sidenote::SideNote,
    ) {
        let Some(vm_step) = vm_step else {
            return;
        };
        let step = &vm_step.step;
        if !matches!(
            step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK)
        ) {
            return;
        }

        // Set OpB to be 17
        traces.fill_columns(row_idx, 17u8, OpB);
    }
    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        _lookup_elements: &stwo_prover::constraint_framework::logup::LookupElements<
            MAX_LOOKUP_TUPLE_SIZE,
        >,
    ) {
        let [is_type_sys] = IsTypeSys::eval(trace_eval);
        // Making sure that op_b=x17
        // (is_type_sys)・ (17 - op_b) = 0
        let [op_b] = trace_eval!(trace_eval, OpB);
        eval.add_constraint(is_type_sys.clone() * (E::F::from(BaseField::from(17)) - op_b));
        // Making sure that op_c=0
        // (is_type_sys)・ (op_c) = 0
        let [op_c] = trace_eval!(trace_eval, crate::column::Column::OpC);
        eval.add_constraint(is_type_sys.clone() * op_c);
        // Computing c_val limbs
        // (is_type_sys)・ (c_val_1) = 0
        // (is_type_sys)・ (c_val_2) = 0
        // (is_type_sys)・ (c_val_3) = 0
        // (is_type_sys)・ (c_val_4) = 0
        let c_val = trace_eval.column_eval::<WORD_SIZE>(crate::column::Column::ValueC);
        for limb in c_val.into_iter() {
            eval.add_constraint(is_type_sys.clone() * limb);
        }
        let instr_val = trace_eval.column_eval::<WORD_SIZE>(crate::column::Column::InstrVal);
        // checking format of instructions - limb 1
        // (is_type_sys) ・ (b01110011 - instr_val_1) = 0
        eval.add_constraint(
            is_type_sys.clone() * (E::F::from(BaseField::from(0b01110011)) - instr_val[0].clone()),
        );
        // checking format of instructions - limb 2
        // (is_type_sys) ・ (b00000000 - instr_val_2) = 0
        eval.add_constraint(
            is_type_sys.clone() * (E::F::from(BaseField::from(0b00000000)) - instr_val[1].clone()),
        );
        // checking format of instructions - limb 3
        // (is_ecall) ・ (b0000 + b0000・2^4 - instr_val_3) = 0
        let [is_ecall] = trace_eval!(trace_eval, IsEcall);
        eval.add_constraint(
            is_ecall.clone() * (E::F::from(BaseField::from(0b0000)) - instr_val[2].clone()),
        );
        // (is_ebreak)・ (b0000 + b1000・2^4 - instr_val_3) = 0
        let [is_ebreak] = trace_eval!(trace_eval, IsEbreak);
        eval.add_constraint(
            is_ebreak.clone()
                * (E::F::from(BaseField::from(0b1000 * (1 << 4))) - instr_val[2].clone()),
        );
        // checking format of instructions - limb 4
        // (is_type_sys) ・ (b00000000 - instr_val_4) = 0
        eval.add_constraint(
            is_type_sys.clone() * (E::F::from(BaseField::from(0b00000000)) - instr_val[3].clone()),
        );
    }
}

#[cfg(test)]
mod test {

    use crate::{
        chips::{
            AddChip, CpuChip, DecodingCheckChip, ProgramMemCheckChip, RangeCheckChip,
            RegisterMemCheckChip, TimestampChip,
        },
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, sidenote::SideNote,
            PreprocessedTraces, TracesBuilder,
        },
    };

    use super::*;
    use nexus_vm::{
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // Set opcode 0x400 in X17
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 17, 0, 0x400),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ECALL), 0, 0, 0),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::EBREAK), 0, 0, 0),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_decode_sys_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            RegisterMemCheckChip,
            ProgramMemCheckChip,
            TimestampChip,
            RangeCheckChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");
        let program_info = view.get_program_memory();

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_trace = ProgramTracesBuilder::new_with_empty_memory(LOG_SIZE, program_info);
        let mut side_note = SideNote::new(&program_trace, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
        }
        assert_chip::<Chips>(traces, Some(program_trace.finalize()));
    }
}
