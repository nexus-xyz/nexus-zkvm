use num_traits::One;
use stwo_prover::{constraint_framework::EvalAtRow, core::fields::m31::BaseField};

use super::utils;
use crate::{
    chips::add_with_carries,
    column::{
        Column::{self, *},
        PreprocessedColumn,
    },
    components::AllLookupElements,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval, trace_eval_next_row, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
    virtual_column::{self, VirtualColumn},
};

use nexus_vm::{
    riscv::{
        BuiltinOpcode,
        InstructionType::{BType, IType, ITypeShamt, JType, RType, SType, UType, Unimpl},
        Register,
    },
    WORD_SIZE,
};

pub struct CpuChip;

impl MachineChip for CpuChip {
    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        _side_note: &mut SideNote,
    ) {
        // Fill ValueAEffectiveFlag to the main trace
        let value_a_effective_flag = match vm_step {
            Some(vm_step) => vm_step.value_a_effectitve_flag(),
            None => false,
        };
        traces.fill_columns(row_idx, value_a_effective_flag, ValueAEffectiveFlag);

        // Fill ValueAEffectiveFlagAux to the main trace
        // Note op_a is u8 so it is always smaller than M31.
        let (value_a_effective_flag_aux, value_a_effective_flag_aux_inv) =
            if let Some(vm_step) = vm_step {
                let op_a = vm_step.get_op_a();
                if op_a == Register::X0 {
                    (BaseField::one(), BaseField::one())
                } else {
                    let op_a_element = BaseField::from(op_a as u32);
                    (BaseField::inverse(&op_a_element), op_a_element)
                }
            } else {
                (BaseField::one(), BaseField::one())
            };

        traces.fill_columns_base_field(
            row_idx,
            &[value_a_effective_flag_aux],
            ValueAEffectiveFlagAux,
        );

        // Fill ValueAEffectiveFlagAuxInv to the main trace
        traces.fill_columns_base_field(
            row_idx,
            &[value_a_effective_flag_aux_inv],
            ValueAEffectiveFlagAuxInv,
        );

        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => {
                // padding
                traces.fill_columns(row_idx, true, IsPadding);
                return;
            }
        };

        let step = &vm_step.step;
        let pc = step.pc;
        // Sanity check: preprocessed column `Clk` contains `row_idx + 1`
        assert!(step.timestamp as usize == row_idx + 1);
        traces.fill_columns(row_idx, pc, Pc);

        // Add opcode to the main trace

        // Set is_opcode to 1, e.g If this is ADD opcode, set IsAdd to 1.
        match step.instruction.opcode.builtin() {
            Some(BuiltinOpcode::ADD) | Some(BuiltinOpcode::ADDI) => {
                traces.fill_columns(row_idx, true, IsAdd);
            }
            Some(BuiltinOpcode::AND) | Some(BuiltinOpcode::ANDI) => {
                traces.fill_columns(row_idx, true, IsAnd);
            }
            Some(BuiltinOpcode::OR) | Some(BuiltinOpcode::ORI) => {
                traces.fill_columns(row_idx, true, IsOr);
            }
            Some(BuiltinOpcode::XOR) | Some(BuiltinOpcode::XORI) => {
                traces.fill_columns(row_idx, true, IsXor);
            }
            Some(BuiltinOpcode::SUB) => {
                traces.fill_columns(row_idx, true, IsSub);
            }
            Some(BuiltinOpcode::SLTU) | Some(BuiltinOpcode::SLTIU) => {
                traces.fill_columns(row_idx, true, IsSltu);
            }
            Some(BuiltinOpcode::SLT) | Some(BuiltinOpcode::SLTI) => {
                traces.fill_columns(row_idx, true, IsSlt);
            }
            Some(BuiltinOpcode::BNE) => {
                traces.fill_columns(row_idx, true, IsBne);
            }
            Some(BuiltinOpcode::BEQ) => {
                traces.fill_columns(row_idx, true, IsBeq);
            }
            Some(BuiltinOpcode::BLTU) => {
                traces.fill_columns(row_idx, true, IsBltu);
            }
            Some(BuiltinOpcode::BLT) => {
                traces.fill_columns(row_idx, true, IsBlt);
            }
            Some(BuiltinOpcode::BGEU) => {
                traces.fill_columns(row_idx, true, IsBgeu);
            }
            Some(BuiltinOpcode::BGE) => {
                traces.fill_columns(row_idx, true, IsBge);
            }
            Some(BuiltinOpcode::JAL) => {
                traces.fill_columns(row_idx, true, IsJal);
            }
            Some(BuiltinOpcode::SB) => {
                traces.fill_columns(row_idx, true, IsSb);
            }
            Some(BuiltinOpcode::SH) => {
                traces.fill_columns(row_idx, true, IsSh);
            }
            Some(BuiltinOpcode::SW) => {
                traces.fill_columns(row_idx, true, IsSw);
            }
            Some(BuiltinOpcode::LUI) => {
                traces.fill_columns(row_idx, true, IsLui);
            }
            Some(BuiltinOpcode::AUIPC) => {
                traces.fill_columns(row_idx, true, IsAuipc);
            }
            Some(BuiltinOpcode::JALR) => {
                traces.fill_columns(row_idx, true, IsJalr);
            }
            Some(BuiltinOpcode::LB) => {
                traces.fill_columns(row_idx, true, IsLb);
            }
            Some(BuiltinOpcode::LH) => {
                traces.fill_columns(row_idx, true, IsLh);
            }
            Some(BuiltinOpcode::LBU) => {
                traces.fill_columns(row_idx, true, IsLbu);
            }
            Some(BuiltinOpcode::LHU) => {
                traces.fill_columns(row_idx, true, IsLhu);
            }
            Some(BuiltinOpcode::LW) => {
                traces.fill_columns(row_idx, true, IsLw);
            }
            Some(BuiltinOpcode::SLL) | Some(BuiltinOpcode::SLLI) => {
                traces.fill_columns(row_idx, true, IsSll);
            }
            Some(BuiltinOpcode::SRL) | Some(BuiltinOpcode::SRLI) => {
                traces.fill_columns(row_idx, true, IsSrl);
            }
            Some(BuiltinOpcode::SRA) | Some(BuiltinOpcode::SRAI) => {
                traces.fill_columns(row_idx, true, IsSra);
            }
            Some(BuiltinOpcode::ECALL) => {
                traces.fill_columns(row_idx, true, IsEcall);
            }
            Some(BuiltinOpcode::EBREAK) => {
                traces.fill_columns(row_idx, true, IsEbreak);
            }
            _ => {
                panic!(
                    "Unsupported opcode: {:?}",
                    step.instruction.opcode.builtin()
                );
            }
        }
        traces.fill_columns(row_idx, pc.wrapping_add(WORD_SIZE as u32), PcNext); // default expectation of the next Pc; might be overwritten by Branch or Jump chips

        // Fill ValueB and ValueC to the main trace
        traces.fill_columns(row_idx, vm_step.get_value_b(), ValueB);

        if step.instruction.ins_type == UType {
            // Fill Imm << 12 to the main trace
            let imm_12 = step.instruction.op_c << 12;
            traces.fill_columns(row_idx, imm_12.to_le_bytes(), ValueC);
        } else {
            traces.fill_columns(row_idx, vm_step.get_value_c(), ValueC);
        }

        // Fill InstructionWord to the main trace
        traces.fill_columns(row_idx, step.raw_instruction, InstrVal);

        // Fill OpA to the main trace
        traces.fill_columns(row_idx, vm_step.get_op_a() as u8, OpA);

        // Fill OpB to the main trace
        let op_b = vm_step.get_op_b() as u8;
        traces.fill_columns(row_idx, op_b, OpB);
        // Fill OpC (register index or immediate value) or ImmC (true if immediate) to the main trace
        let op_c_raw = vm_step.step.instruction.op_c;
        match vm_step.step.instruction.ins_type {
            RType => {
                traces.fill_columns(row_idx, op_c_raw as u8, OpC);
            }
            BType | JType => {
                let (_, op_c_bits) = vm_step.get_value_c();
                // immediate sign is part of instruction word and is used for decoding constraints.
                let op_c_sign_extended = utils::sign_extend(op_c_raw, op_c_bits);

                traces.fill_columns(
                    row_idx,
                    BaseField::from_u32_unchecked(op_c_sign_extended),
                    OpC,
                );
                traces.fill_columns(row_idx, true, ImmC);
            }
            IType | SType | ITypeShamt | UType => {
                let (op_c_word, op_c_bits) = vm_step.get_value_c();
                assert_eq!(op_c_raw, u32::from_le_bytes(op_c_word));
                let op_c_zero_extended = op_c_raw & ((1u32 << op_c_bits) - 1);
                traces.fill_columns(
                    row_idx,
                    BaseField::from_u32_unchecked(op_c_zero_extended),
                    OpC,
                );
                traces.fill_columns(row_idx, true, ImmC); // ImmC is a boolean flag
            }
            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }

        // Fill register access flags in the main trace
        // We use Reg3 for the destination because Reg{1,2,3} have to be accessed in this order.
        match vm_step.step.instruction.ins_type {
            RType => {
                // Reg1Accessed has been replaced with virtual column OpBFlag
                traces.fill_columns(row_idx, vm_step.step.instruction.op_b as u8, Reg1Address);
                // Reg2Accessed has been replaced with virtual column IsTypeR
                traces.fill_columns(row_idx, vm_step.step.instruction.op_c as u8, Reg2Address);
                // Reg3Accessed is now a virtual column
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            IType | ITypeShamt => {
                // Reg1Accessed has been replaced with virtual column OpBFlag
                traces.fill_columns(row_idx, vm_step.get_op_b() as u8, Reg1Address);
                traces.fill_columns(row_idx, vm_step.get_op_a() as u8, Reg3Address);
            }
            UType => {
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            BType | SType => {
                // Reg1Accessed has been replaced with virtual column OpBFlag
                traces.fill_columns(row_idx, vm_step.step.instruction.op_b as u8, Reg1Address);
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            JType => {
                traces.fill_columns(row_idx, vm_step.step.instruction.op_a as u8, Reg3Address);
            }
            Unimpl => {
                panic!(
                    "Unsupported instruction type: {:?}",
                    vm_step.step.instruction.ins_type
                );
            }
        }

        // Fill PcCarry
        // PcCarry isn't used in jump or branch instructions, but we fill it anyway.
        let (_, pc_carry) = add_with_carries(pc.to_le_bytes(), 4u32.to_le_bytes());
        traces.fill_columns(row_idx, pc_carry, PcCarry);
    }

    fn add_constraints<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
    ) {
        let [is_padding] = trace_eval!(trace_eval, IsPadding);
        // Padding rows should not access registers
        let [next_is_padding] = trace_eval_next_row!(trace_eval, Column::IsPadding);

        // Padding cannot go from 1 to zero, unless the current line is the first
        // TODO: consider forcing IsPadding == 0 on the first row, if we prefer to ban zero-step empty executions.
        let [next_is_first] = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsLast);
        eval.add_constraint(
            (E::F::one() - next_is_first.clone())
                * is_padding.clone()
                * (E::F::one() - next_is_padding.clone()),
        );

        // Constrain ValueAEffectiveFlag's range
        let [value_a_effective_flag] = trace_eval!(trace_eval, ValueAEffectiveFlag);

        let [value_a_effective_flag_aux] = trace_eval!(trace_eval, ValueAEffectiveFlagAux);
        let [value_a_effective_flag_aux_inv] = trace_eval!(trace_eval, ValueAEffectiveFlagAuxInv);
        // Below is just for making sure value_a_effective_flag_aux is not zero.
        eval.add_constraint(
            value_a_effective_flag_aux.clone() * value_a_effective_flag_aux_inv - E::F::one(),
        );
        let [op_a] = trace_eval!(trace_eval, OpA);
        // Since value_a_effective_flag_aux is non-zero, below means: op_a is zero if and only if value_a_effective_flag is zero.
        // Combined with value_a_effective_flag's range above, this determines value_a_effective_flag uniquely.
        eval.add_constraint(
            op_a.clone() * value_a_effective_flag_aux - value_a_effective_flag.clone(),
        );
        // Sum of IsOp flags is one. Combined with the range-checks in RangeBoolChip, the constraint implies exactly one of these flags is set.
        let [is_add] = trace_eval!(trace_eval, IsAdd);
        let [is_sub] = trace_eval!(trace_eval, IsSub);
        let [is_and] = trace_eval!(trace_eval, IsAnd);
        let [is_or] = trace_eval!(trace_eval, IsOr);
        let [is_xor] = trace_eval!(trace_eval, IsXor);
        let [is_slt] = trace_eval!(trace_eval, IsSlt);
        let [is_sltu] = trace_eval!(trace_eval, IsSltu);
        let [is_bne] = trace_eval!(trace_eval, IsBne);
        let [is_beq] = trace_eval!(trace_eval, IsBeq);
        let [is_bltu] = trace_eval!(trace_eval, IsBltu);
        let [is_blt] = trace_eval!(trace_eval, IsBlt);
        let [is_bgeu] = trace_eval!(trace_eval, IsBgeu);
        let [is_bge] = trace_eval!(trace_eval, IsBge);
        let [is_jal] = trace_eval!(trace_eval, IsJal);
        let [is_lui] = trace_eval!(trace_eval, IsLui);
        let [is_auipc] = trace_eval!(trace_eval, IsAuipc);
        let [is_jalr] = trace_eval!(trace_eval, IsJalr);
        let [is_sll] = trace_eval!(trace_eval, IsSll);
        let [is_srl] = trace_eval!(trace_eval, IsSrl);
        let [is_sra] = trace_eval!(trace_eval, IsSra);
        let [is_padding] = trace_eval!(trace_eval, IsPadding);
        let [is_sb] = trace_eval!(trace_eval, IsSb);
        let [is_sh] = trace_eval!(trace_eval, IsSh);
        let [is_sw] = trace_eval!(trace_eval, IsSw);
        let [is_lb] = trace_eval!(trace_eval, IsLb);
        let [is_lh] = trace_eval!(trace_eval, IsLh);
        let [is_lbu] = trace_eval!(trace_eval, IsLbu);
        let [is_lhu] = trace_eval!(trace_eval, IsLhu);
        let [is_lw] = trace_eval!(trace_eval, IsLw);
        let [is_ecall] = trace_eval!(trace_eval, IsEcall);
        let [is_ebreak] = trace_eval!(trace_eval, IsEbreak);
        eval.add_constraint(
            is_add.clone()
                + is_sub.clone()
                + is_and.clone()
                + is_or.clone()
                + is_xor.clone()
                + is_slt.clone()
                + is_sltu.clone()
                + is_bne.clone()
                + is_beq.clone()
                + is_bltu.clone()
                + is_bgeu.clone()
                + is_blt.clone()
                + is_bge.clone()
                + is_jal.clone()
                + is_sb.clone()
                + is_sh.clone()
                + is_sw.clone()
                + is_lui.clone()
                + is_auipc.clone()
                + is_jalr.clone()
                + is_lb.clone()
                + is_lbu.clone()
                + is_lh.clone()
                + is_lhu.clone()
                + is_lw.clone()
                + is_sll.clone()
                + is_srl.clone()
                + is_sra.clone()
                + is_ecall.clone()
                + is_ebreak.clone()
                + is_padding
                - E::F::one(),
        );

        // is_type_r = (1-imm_c) ・(is_add + is_sub + is_slt + is_sltu + is_xor + is_or + is_and + is_sll + is_srl + is_sra)
        let [is_type_r] = virtual_column::IsTypeR::eval(trace_eval);

        // is_type_i = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift
        let [is_type_i] = virtual_column::IsTypeI::eval(trace_eval);

        // Constrain Reg{1,2,3}Address uniquely for type R and type I instructions
        let [op_b] = trace_eval!(trace_eval, Column::OpB);
        let [op_c] = trace_eval!(trace_eval, Column::OpC);
        let [reg1_address] = trace_eval!(trace_eval, Column::Reg1Address);
        let [reg2_address] = trace_eval!(trace_eval, Column::Reg2Address);
        let [reg3_address] = trace_eval!(trace_eval, Column::Reg3Address);
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (op_b.clone() - reg1_address.clone()),
        );
        eval.add_constraint(is_type_r.clone() * (op_c.clone() - reg2_address.clone()));
        eval.add_constraint(
            (is_type_r.clone() + is_type_i.clone()) * (op_a.clone() - reg3_address.clone()),
        );

        // Constrain read access doesn't change register values for type R and type I instructions
        let reg1_val_prev = trace_eval!(trace_eval, Column::Reg1ValPrev);
        let reg2_val_prev = trace_eval!(trace_eval, Column::Reg2ValPrev);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                (is_type_r.clone() + is_type_i.clone())
                    * (reg1_val_prev[limb_idx].clone() - value_b[limb_idx].clone()),
            );
            eval.add_constraint(
                is_type_r.clone() * (reg2_val_prev[limb_idx].clone() - value_c[limb_idx].clone()),
            );
        }

        // is_type_b = is_beq + is_bne + is_blt + is_bge + is_bltu + is_bgeu
        let is_type_b = is_beq + is_bne + is_bltu + is_bgeu + is_blt + is_bge;

        // is_type_s = is_sb + is_sh + is_sw
        let [is_type_s] = virtual_column::IsTypeS::eval(trace_eval);

        // type S and type B access registers in similar ways
        let is_type_b_s = is_type_b + is_type_s;

        // Constraint reg{1,2,3}_address uniquely for type B and type S instructions
        eval.add_constraint(is_type_b_s.clone() * (op_b.clone() - reg1_address.clone()));
        // Always using reg3 for ValueA and OpA, even when it's not the destination; this simplifies the register memory checking.
        eval.add_constraint(is_type_b_s.clone() * (op_a.clone() - reg3_address.clone()));

        let reg3_val_prev = trace_eval!(trace_eval, Column::Reg3ValPrev);
        let value_a = trace_eval!(trace_eval, Column::ValueA);

        // Constrain read access doesn't change register values for type B and type S instructions
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                is_type_b_s.clone() * (reg1_val_prev[limb_idx].clone() - value_b[limb_idx].clone()),
            );
            eval.add_constraint(
                is_type_b_s.clone() * (reg3_val_prev[limb_idx].clone() - value_a[limb_idx].clone()),
            );
        }

        let is_type_sys = is_ebreak + is_ecall;
        let [is_sys_halt] = trace_eval!(trace_eval, Column::IsSysHalt);

        // Constraint reg{1,2,3}_address uniquely for type SYS instructions
        eval.add_constraint(is_type_sys.clone() * (op_b - reg1_address));
        eval.add_constraint(is_type_sys.clone() * (op_c - reg2_address)); // not currently used; a future syscall might use it
        eval.add_constraint(is_type_sys.clone() * (op_a - reg3_address));

        // PcNext should be Pc on the next row, unless the next row is the first row or padding.
        let pc_next = trace_eval!(trace_eval, Column::PcNext);
        let pc_on_next_row = trace_eval_next_row!(trace_eval, Column::Pc);
        for limb_idx in 0..WORD_SIZE {
            eval.add_constraint(
                (E::F::one() - next_is_first.clone())
                    * (E::F::one() - next_is_padding.clone())
                    * (pc_next[limb_idx].clone() - pc_on_next_row[limb_idx].clone()),
            );
        }

        // Increment PC by four
        // (is_pc_incremented)・(pc_next_1 + pc_carry_1·2^8 - pc_1 - 4) = 0
        let [is_pc_incremented] = virtual_column::IsPcIncremented::eval(trace_eval);
        let pc_carry = trace_eval!(trace_eval, Column::PcCarry);
        let pc = trace_eval!(trace_eval, Column::Pc);
        eval.add_constraint(
            is_pc_incremented.clone()
                * (pc_next[0].clone() + pc_carry[0].clone() * BaseField::from(1 << 8)
                    - pc[0].clone()
                    - BaseField::from(4).into()),
        );
        // (is_pc_incremented)・(pc_next_2 + pc_carry_2·2^8 - pc_2 - pc_carry_1) = 0
        // (is_pc_incremented)・(pc_next_3 + pc_carry_3·2^8 - pc_3 - pc_carry_2) = 0
        // (is_pc_incremented)・(pc_next_4 + pc_carry_4·2^8 - pc_4 - pc_carry_3) = 0
        for limb_idx in 1..WORD_SIZE {
            eval.add_constraint(
                is_pc_incremented.clone()
                    * (pc_next[limb_idx].clone()
                        + pc_carry[limb_idx].clone() * BaseField::from(1 << 8)
                        - pc[limb_idx].clone()
                        - pc_carry[limb_idx - 1].clone()),
            );
        }

        // Setting pc_next = pc when is_sys_halt=1 or pc_next = pc+4 for other flags
        // pc_carry_{1,2,3,4} used for carry handling
        // is_type_sys・(4・(1-is_sys_halt) + pc_1 - pc_carry_1·2^8 - pc_next_1) = 0
        // is_type_sys・(pc_2 + pc_carry_1 - pc_carry_2·2^8 - pc_next_2) = 0
        // is_type_sys・(pc_3 + pc_carry_2 - pc_carry_3·2^8 - pc_next_3) = 0
        // is_type_sys・(pc_4 + pc_carry_3 - pc_carry_4·2^8 - pc_next_4) = 0
        eval.add_constraint(
            is_type_sys.clone()
                * (E::F::from(BaseField::from(4)) * (E::F::one() - is_sys_halt.clone())
                    + pc[0].clone()
                    - pc_carry[0].clone() * BaseField::from(1 << 8)
                    - pc_next[0].clone()),
        );

        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_type_sys.clone()
                    * (pc[i].clone() + pc_carry[i - 1].clone()
                        - pc_carry[i].clone() * BaseField::from(1 << 8)
                        - pc_next[i].clone()),
            );
        }
    }
}
