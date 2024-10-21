use num_traits::Zero;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use nexus_common::cpu::Registers;
use nexus_vm::riscv::{BuiltinOpcode, Register};

use crate::{
    machine2::{
        column::Column::{self, *},
        trace::{
            eval::{trace_eval, TraceEval},
            trace_column, trace_column_mut, Step, Traces,
        },
        traits::MachineChip,
    },
    utils::WORD_SIZE,
};

pub struct AddChip;
impl MachineChip for AddChip {
    fn fill_main_trace(traces: &mut Traces, row_idx: usize, vm_step: &Step) {
        let step = &vm_step.step;
        let regs = &vm_step.regs;
        if !matches!(step.instruction.opcode.builtin(), Some(BuiltinOpcode::ADD)) {
            return;
        }

        // TODO: handle no-op case when rd = 0.
        assert!(step.instruction.op_a != Register::X0);
        debug_assert! {{
            let is_add = trace_column!(traces, row_idx, IsAdd);
            !is_add[0].is_zero()
        }};

        let rs1 = step.instruction.op_b;
        let rs2 = step.instruction.op_c;

        let rs1_val = regs.read(rs1);
        let rs2_val = regs.read(Register::from(
            u8::try_from(rs2).expect("immediate not supported"),
        ));

        let rs1_bytes = rs1_val.to_le_bytes();
        let rs2_bytes = rs2_val.to_le_bytes();
        let rd_bytes = rs1_val.wrapping_add(rs2_val).to_le_bytes();

        let mut carry_vals = [0u32; WORD_SIZE];

        for i in 0..WORD_SIZE {
            let prev_carry = i.checked_sub(1).map(|j| carry_vals[j]).unwrap_or(0u32);
            if rs1_bytes[i] as u32 + rs2_bytes[i] as u32 + prev_carry > 255 {
                carry_vals[i] = 1
            }
        }
        // Assume that values for rs1 and rs2 are filled by cpu.
        //
        // let r1_val = trace_column!(traces, row_idx, ValueB);
        // let r2_val = trace_column!(traces, row_idx, ValueC);

        // fill traces
        let rd_val = trace_column_mut!(traces, row_idx, ValueA);
        for (i, b) in rd_bytes.iter().enumerate() {
            *rd_val[i] = BaseField::from(*b as u32);
        }
        let carry = trace_column_mut!(traces, row_idx, CarryFlag);
        for (i, c) in carry_vals.iter().enumerate() {
            *carry[i] = BaseField::from(*c);
        }
    }

    fn add_constraints<E: EvalAtRow>(eval: &mut E, trace_eval: &TraceEval<E>) {
        let (_, is_add) = trace_eval!(trace_eval, IsAdd);
        let is_add = is_add[0];
        // modulus for 8-bit limbs
        let modulus = E::F::from(256u32.into());

        let (_, carry_flag) = trace_eval!(trace_eval, CarryFlag);
        let (_, rs1_val) = trace_eval!(trace_eval, ValueB);
        let (_, rs2_val) = trace_eval!(trace_eval, ValueC);
        let (_, rd_val) = trace_eval!(trace_eval, ValueA);

        for i in 0..WORD_SIZE {
            let carry = i
                .checked_sub(1)
                .map(|j| carry_flag[j])
                .unwrap_or(E::F::zero());

            // ADD a, b, c
            // rdval[i] + h1[i] * 2^8 = rs1val[i] + rs2val[i] + h1[i - 1]
            eval.add_constraint(
                is_add * (rd_val[i] + carry_flag[i] * modulus - (rs1_val[i] + rs2_val[i] + carry)),
            );
        }
        // Range checks should differentiate ADD and ADDI cases, as immediate values are smaller.
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nexus_common::cpu::Registers;
    use nexus_vm::{
        cpu::RegisterFile,
        riscv::{BuiltinOpcode, Instruction, InstructionType, Opcode},
        trace as vm_trace,
    };
    use num_traits::One;
    use stwo_prover::{
        constraint_framework::assert_constraints,
        core::{
            backend::CpuBackend,
            pcs::TreeVec,
            poly::{
                circle::{CanonicCoset, CircleEvaluation},
                BitReversedOrder,
            },
        },
    };

    const ROW_IDX: usize = 0;
    const LOG_SIZE: u32 = 6;

    const VALS: [(u32, u32); 5] = [
        (0u32, 0u32),
        (u32::MAX, 0),
        (u32::MAX, u32::MAX),
        (u32::MAX - 1, u32::MAX / 2),
        (1 << 16, 10),
    ];

    fn gen_add(rs1val: u32, rs2val: u32) -> [[u8; WORD_SIZE]; 3] {
        let output = rs1val.wrapping_add(rs2val);
        let a = rs1val.to_le_bytes();
        let b = rs2val.to_le_bytes();
        let output = output.to_le_bytes();

        [a, b, output]
    }

    fn gen_traces(rs1val: u32, rs2val: u32) -> ([u8; WORD_SIZE], Traces) {
        let [r1_val, r2_val, output] = gen_add(rs1val, rs2val);

        let mut traces = Traces::new(LOG_SIZE);
        let inst = Instruction::new(
            Opcode::from(BuiltinOpcode::ADD),
            1,
            2,
            3,
            InstructionType::RType,
        );
        let mut regs = RegisterFile::new();
        regs.write(Register::X2, rs1val);
        regs.write(Register::X3, rs2val);

        let step = Step {
            step: vm_trace::Step {
                instruction: inst,
                result: None,
                ..Default::default()
            },
            regs,
        };
        *trace_column_mut!(traces, ROW_IDX, IsAdd)[0] = BaseField::one();

        let r1_col = trace_column_mut!(traces, ROW_IDX, ValueB);
        for (i, b) in r1_val.iter().enumerate() {
            *r1_col[i] = BaseField::from(*b as u32);
        }
        let r2_col = trace_column_mut!(traces, ROW_IDX, ValueC);
        for (i, b) in r2_val.iter().enumerate() {
            *r2_col[i] = BaseField::from(*b as u32);
        }
        AddChip::fill_main_trace(&mut traces, ROW_IDX, &step);
        (output, traces)
    }

    #[test]
    fn add_chip_trace() {
        for (i, (rs1val, rs2val)) in VALS.into_iter().enumerate() {
            let (output, traces) = gen_traces(rs1val, rs2val);

            let rd_val =
                trace_column!(traces, ROW_IDX, ValueA).map(|limb| u8::try_from(limb.0).unwrap());

            assert_eq!(output, rd_val, "{i}: r1_val: {rs1val} r2_val: {rs2val}");
        }
    }

    #[test]
    fn constraints_satisfied() {
        for (rs1val, rs2val) in VALS {
            let (_, traces) = gen_traces(rs1val, rs2val);

            let domain = CanonicCoset::new(LOG_SIZE as u32).circle_domain();
            let traces: Vec<CircleEvaluation<_, _, _>> = traces
                .into_inner()
                .into_iter()
                .map(|eval| CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, eval))
                .collect();

            let traces = TreeVec::new(vec![traces]);
            let trace_polys = traces.map(|trace| {
                trace
                    .into_iter()
                    .map(|c| c.interpolate())
                    .collect::<Vec<_>>()
            });
            assert_constraints(
                &trace_polys,
                CanonicCoset::new(LOG_SIZE as u32),
                |mut eval| {
                    let trace_eval = TraceEval::new(&mut eval);
                    AddChip::add_constraints(&mut eval, &trace_eval);
                },
            );
        }
    }
}
