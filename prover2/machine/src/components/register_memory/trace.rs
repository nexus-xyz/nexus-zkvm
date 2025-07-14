use num_traits::{One, Zero};
use stwo_prover::core::{
    backend::simd::{column::BaseColumn, m31::LOG_N_LANES},
    fields::m31::BaseField,
};

use nexus_common::riscv::register::NUM_REGISTERS;
use nexus_vm::{
    riscv::{BuiltinOpcode, InstructionType},
    WORD_SIZE,
};
use nexus_vm_prover_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    program::ProgramStep,
};

use super::columns::Column;
use crate::{components::utils::decr_subtract_with_borrow, side_note::SideNote};

// Register memory side note can only be updated by the register memory component, once it's stored
// in the prover's side note it can only be used to fetch final registers state.

#[derive(Debug, Default)]
pub struct RegisterMemorySideNote {
    last_access_timestamp: [u32; NUM_REGISTERS],
    last_access_value: [u32; NUM_REGISTERS],
}

struct AccessResult {
    prev_timestamp: u32,
    prev_value: u32,
}

impl RegisterMemorySideNote {
    pub fn timestamps(&self) -> &[u32; NUM_REGISTERS] {
        &self.last_access_timestamp
    }

    pub fn values(&self) -> &[u32; NUM_REGISTERS] {
        &self.last_access_value
    }

    fn access(&mut self, reg: u8, cur_timestamp: u32, cur_value: u32) -> AccessResult {
        assert!((reg as usize) < NUM_REGISTERS);
        let ret = AccessResult {
            prev_timestamp: self.last_access_timestamp[reg as usize],
            prev_value: self.last_access_value[reg as usize],
        };
        self.last_access_timestamp[reg as usize] = cur_timestamp;
        self.last_access_value[reg as usize] = cur_value;
        ret
    }
}

pub fn preprocessed_timestamp_trace(log_size: u32, shift: u32) -> Vec<BaseColumn> {
    assert!(shift < 3);
    let mut result = vec![];

    for i in 0..WORD_SIZE {
        let col_iter = (1..=1 << log_size).map(|clk| ((3 * clk - shift) >> (i * 8)) & 255);
        result.push(BaseColumn::from_iter(col_iter.map(BaseField::from)));
    }
    result
}

pub fn generate_main_trace(side_note: &mut SideNote) -> FinalizedTrace {
    // Main routine for generating register-memory trace.

    assert_initial_state(&side_note.memory.register_memory);
    let num_steps = side_note.num_program_steps();
    let log_size = num_steps.next_power_of_two().ilog2().max(LOG_N_LANES);

    let mut trace = TraceBuilder::new(log_size);
    let mut reg_mem_side_note = RegisterMemorySideNote::default();

    for (row_idx, program_step) in side_note.iter_program_steps().enumerate() {
        generate_trace_row(&mut trace, row_idx, program_step, &mut reg_mem_side_note);
    }

    // store final register state into side note
    side_note.memory.register_memory = reg_mem_side_note;

    for row_idx in num_steps..1 << log_size {
        trace.fill_columns(row_idx, true, Column::IsLocalPad);
        trace.fill_columns(row_idx, BaseField::one(), Column::Reg3ValEffectiveFlagAux);
        trace.fill_columns(
            row_idx,
            BaseField::one(),
            Column::Reg3ValEffectiveFlagAuxInv,
        );
    }
    trace.finalize()
}

fn assert_initial_state(register_mem_side_note: &RegisterMemorySideNote) {
    assert!(
        register_mem_side_note
            .last_access_timestamp
            .iter()
            .all(Zero::is_zero),
        "register memory initial timestamps are invalid"
    );
    assert!(
        register_mem_side_note
            .last_access_value
            .iter()
            .all(Zero::is_zero),
        "register memory initial values are invalid"
    );
}

fn reg1_accessed(step: ProgramStep) -> bool {
    let opcode = &step.step.instruction.opcode;
    !matches!(
        opcode.builtin(),
        Some(BuiltinOpcode::LUI) | Some(BuiltinOpcode::AUIPC) | Some(BuiltinOpcode::JAL)
    )
}

fn reg2_accessed(step: ProgramStep) -> bool {
    matches!(step.step.instruction.ins_type, InstructionType::RType)
}

fn reg3_accessed(step: ProgramStep) -> bool {
    let opcode = &step.step.instruction.opcode;

    // TODO: handle syscalls
    assert!(
        !matches!(
            opcode.builtin(),
            Some(BuiltinOpcode::ECALL) | Some(BuiltinOpcode::EBREAK)
        ),
        "register memory doesn't support syscalls"
    );

    true
}

fn reg3_write(step: ProgramStep) -> bool {
    let instr = &step.step.instruction;

    !matches!(
        instr.ins_type,
        InstructionType::SType | InstructionType::BType
    )
}

fn generate_trace_row(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    program_step: ProgramStep,
    reg_mem_side_note: &mut RegisterMemorySideNote,
) {
    let opcode = &program_step.step.instruction.opcode;
    assert!(opcode.is_builtin(), "custom instructions are unsupported");

    let clk = program_step.step.timestamp;
    let reg1_cur_ts = clk * 3 - 2;
    let reg2_cur_ts = clk * 3 - 1;
    let reg3_cur_ts = clk * 3;

    let reg1_accessed = reg1_accessed(program_step);
    let reg2_accessed = reg2_accessed(program_step);
    let reg3_accessed = reg3_accessed(program_step);

    let reg1_addr = program_step.get_op_b() as u8;
    let reg2_addr = program_step.get_op_c();
    let reg3_addr = program_step.get_op_a() as u8;

    let reg1_value = program_step.get_value_b();
    let reg2_value = if program_step.step.instruction.ins_type == InstructionType::UType {
        (program_step.step.instruction.op_c << 12).to_le_bytes()
    } else {
        program_step.get_value_c().0
    };
    let reg3_value = program_step.get_reg3_result_value();

    let reg3_value_effective_flag = program_step.value_a_effective_flag();
    let (reg3_value_effective_flag_aux, reg3_value_effective_flag_aux_inv): (BaseField, u8) = {
        if reg3_value_effective_flag {
            (BaseField::from(reg3_addr as u32).inverse(), reg3_addr)
        } else {
            (BaseField::one(), 1)
        }
    };
    let reg3_value_cur = if reg3_value_effective_flag {
        reg3_value
    } else {
        // x0
        [0; WORD_SIZE]
    };
    trace.fill_columns(
        row_idx,
        reg3_value_effective_flag,
        Column::Reg3ValEffectiveFlag,
    );
    trace.fill_columns(
        row_idx,
        reg3_value_effective_flag_aux,
        Column::Reg3ValEffectiveFlagAux,
    );
    trace.fill_columns(
        row_idx,
        reg3_value_effective_flag_aux_inv,
        Column::Reg3ValEffectiveFlagAuxInv,
    );

    let reg1_prev_ts = if reg1_accessed {
        generate_prev_access(
            trace,
            row_idx,
            reg1_addr,
            reg1_value,
            reg_mem_side_note,
            reg1_cur_ts,
            Column::Reg1TsPrev,
        )
        .1
    } else {
        0
    };
    let reg2_prev_ts = if reg2_accessed {
        let reg2_addr = u8::try_from(reg2_addr).expect("invalid value of reg2-addr");
        generate_prev_access(
            trace,
            row_idx,
            reg2_addr,
            reg2_value,
            reg_mem_side_note,
            reg2_cur_ts,
            Column::Reg2TsPrev,
        )
        .1
    } else {
        0
    };
    let reg3_prev_ts = if reg3_accessed {
        let (reg3_prev_value, reg3_prev_ts) = generate_prev_access(
            trace,
            row_idx,
            reg3_addr,
            reg3_value_cur,
            reg_mem_side_note,
            reg3_cur_ts,
            Column::Reg3TsPrev,
        );

        // write reg3 previous value
        trace.fill_columns(row_idx, reg3_prev_value, Column::Reg3ValPrev);
        trace.fill_columns(row_idx, reg3_write(program_step), Column::Reg3Write);
        reg3_prev_ts
    } else {
        0
    };

    if reg1_accessed {
        trace.fill_columns(row_idx, reg1_addr, Column::Reg1Addr);
        trace.fill_columns(row_idx, reg1_value, Column::Reg1Val);
    }
    if reg2_accessed {
        trace.fill_columns(row_idx, BaseField::from(reg2_addr), Column::Reg2Addr);
        trace.fill_columns(row_idx, reg2_value, Column::Reg2Val);
    }
    if reg3_accessed {
        trace.fill_columns(row_idx, reg3_addr, Column::Reg3Addr);
        trace.fill_columns(row_idx, reg3_value, Column::Reg3Val);
        trace.fill_columns(row_idx, reg3_value_cur, Column::Reg3ValCur);
    }

    trace.fill_columns(row_idx, reg1_accessed, Column::Reg1Accessed);
    trace.fill_columns(row_idx, reg2_accessed, Column::Reg2Accessed);
    trace.fill_columns(row_idx, reg3_accessed, Column::Reg3Accessed);

    // timestamp aux columns
    let (reg1_ts_prev_aux, h1_aux_borrow) =
        decr_subtract_with_borrow(reg1_cur_ts.to_le_bytes(), reg1_prev_ts.to_le_bytes());
    let (reg2_ts_prev_aux, h2_aux_borrow) =
        decr_subtract_with_borrow(reg2_cur_ts.to_le_bytes(), reg2_prev_ts.to_le_bytes());
    let (reg3_ts_prev_aux, h3_aux_borrow) =
        decr_subtract_with_borrow(reg3_cur_ts.to_le_bytes(), reg3_prev_ts.to_le_bytes());
    assert!(!h1_aux_borrow[3]);
    assert!(!h2_aux_borrow[3]);
    assert!(!h3_aux_borrow[3]);

    trace.fill_columns(row_idx, reg1_ts_prev_aux, Column::Reg1TsPrevAux);
    trace.fill_columns(row_idx, reg2_ts_prev_aux, Column::Reg2TsPrevAux);
    trace.fill_columns(row_idx, reg3_ts_prev_aux, Column::Reg3TsPrevAux);
    trace.fill_columns(row_idx, h1_aux_borrow[1], Column::H1AuxBorrow);
    trace.fill_columns(row_idx, h2_aux_borrow[1], Column::H2AuxBorrow);
    trace.fill_columns(row_idx, h3_aux_borrow[1], Column::H3AuxBorrow);
}

fn generate_prev_access(
    trace: &mut TraceBuilder<Column>,
    row_idx: usize,
    reg_addr: u8,
    reg_value: [u8; WORD_SIZE],
    reg_memory_side_note: &mut RegisterMemorySideNote,
    reg_cur_ts: u32,
    dst_ts: Column,
) -> (u32, u32) {
    let curr_value = u32::from_le_bytes(reg_value);
    assert!(
        reg_addr != 0 || curr_value == 0,
        "writing non-zero to X0, reg_idx: {}, cur_value: {}, row_idx: {}",
        reg_addr,
        curr_value,
        row_idx
    );
    let AccessResult {
        prev_timestamp,
        prev_value,
    } = reg_memory_side_note.access(reg_addr, reg_cur_ts, curr_value);
    trace.fill_columns(row_idx, prev_timestamp, dst_ts);
    (prev_value, prev_timestamp)
}
