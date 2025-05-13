use nexus_common::constants::WORD_SIZE_HALVED;
use nexus_vm::{memory::MemAccessSize, riscv::BuiltinOpcode, WORD_SIZE};
use num_traits::One;
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow, Relation, RelationEntry},
    core::{
        backend::simd::m31::{PackedBaseField, LOG_N_LANES},
        fields::m31::BaseField,
    },
};

use crate::{
    chips::memory_check::decr_subtract_with_borrow,
    column::{
        Column::{
            self, Helper1, Helper2, Helper3, Helper4, IsLb, IsLbu, IsLh, IsLhu, IsLw, IsSb, IsSh,
            IsSw, Ram1TsPrev, Ram1TsPrevAux, Ram1ValCur, Ram1ValPrev, Ram2TsPrev, Ram2TsPrevAux,
            Ram2ValCur, Ram2ValPrev, Ram3TsPrev, Ram3TsPrevAux, Ram3ValCur, Ram3ValPrev,
            Ram4TsPrev, Ram4TsPrevAux, Ram4ValCur, Ram4ValPrev,
        },
        PreprocessedColumn,
    },
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{preprocessed_trace_eval, trace_eval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder, Word,
    },
    traits::MachineChip,
    virtual_column::{IsLoad, IsTypeS, VirtualColumn, VirtualColumnForSum},
};

use super::add::add_with_carries;

/// A virtual column that indicates the first byte RAM access
struct Ram1Accessed;

impl VirtualColumnForSum for Ram1Accessed {
    fn columns() -> &'static [Column] {
        &[IsSb, IsSh, IsSw, IsLb, IsLh, IsLbu, IsLhu, IsLw]
    }
}

/// A virtual column that indicates the second byte RAM access
struct Ram2Accessed;

impl VirtualColumnForSum for Ram2Accessed {
    fn columns() -> &'static [Column] {
        &[IsSh, IsSw, IsLh, IsLhu, IsLw]
    }
}

/// A virtual column that indicates the third and the fourth byte RAM access
struct Ram3_4Accessed;

impl VirtualColumnForSum for Ram3_4Accessed {
    fn columns() -> &'static [Column] {
        &[IsSw, IsLw]
    }
}

// Support SB, SH, SW, LB, LH and LW opcodes
pub struct LoadStoreChip;

const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE_HALVED + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);

impl MachineChip for LoadStoreChip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
        _config: &ExtensionsConfig,
    ) {
        all_elements.insert(LoadStoreLookupElements::draw(channel));
    }

    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        _config: &ExtensionsConfig,
    ) {
        let vm_step = match vm_step {
            Some(vm_step) => vm_step,
            None => return,
        };
        if !matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::SB)
                | Some(BuiltinOpcode::SH)
                | Some(BuiltinOpcode::SW)
                | Some(BuiltinOpcode::LB)
                | Some(BuiltinOpcode::LH)
                | Some(BuiltinOpcode::LBU)
                | Some(BuiltinOpcode::LHU)
                | Some(BuiltinOpcode::LW)
        ) {
            return;
        }

        let is_load = matches!(
            vm_step.step.instruction.opcode.builtin(),
            Some(BuiltinOpcode::LB)
                | Some(BuiltinOpcode::LH)
                | Some(BuiltinOpcode::LW)
                | Some(BuiltinOpcode::LBU)
                | Some(BuiltinOpcode::LHU)
        );

        let value_a = vm_step.get_value_a();
        traces.fill_columns(row_idx, value_a, Column::ValueA);
        let value_b = vm_step.get_value_b();
        let (offset, effective_bits) = vm_step.get_value_c();
        assert_eq!(effective_bits, 12);
        let (ram_base_address, carry_bits) = if is_load {
            add_with_carries(value_b, offset)
        } else {
            add_with_carries(value_a, offset)
        };
        traces.fill_columns(row_idx, ram_base_address, Column::RamBaseAddr);
        let carry_bits = [carry_bits[1], carry_bits[3]];
        traces.fill_columns(row_idx, carry_bits, Column::CarryFlag);
        let clk = row_idx as u32 + 1;
        for memory_record in vm_step.step.memory_records.iter() {
            assert_eq!(
                memory_record.get_timestamp(),
                (row_idx as u32 + 1),
                "timestamp mismatch"
            );
            assert_eq!(memory_record.get_timestamp(), clk, "timestamp mismatch");
            let byte_address = memory_record.get_address();
            assert_eq!(
                byte_address,
                u32::from_le_bytes(ram_base_address),
                "address mismatch"
            );

            let size = memory_record.get_size() as usize;

            if !is_load {
                assert!(
                    (memory_record.get_prev_value().unwrap() as u64) < { 1u64 } << (size * 8),
                    "a memory operation contains a too big prev value"
                );
            }
            assert!(
                (memory_record.get_value() as u64) < { 1u64 } << (size * 8),
                "a memory operation contains a too big value"
            );

            if is_load {
                let cur_value_extended = vm_step
                    .step
                    .result
                    .expect("load operation should have a result");
                match memory_record.get_size() {
                    MemAccessSize::Byte => {
                        assert_eq!(cur_value_extended & 0xff, memory_record.get_value() & 0xff);
                        traces.fill_columns(
                            row_idx,
                            (cur_value_extended & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::HalfWord => {
                        assert_eq!(
                            cur_value_extended & 0xffff,
                            memory_record.get_value() & 0xffff
                        );
                        traces.fill_columns(
                            row_idx,
                            ((cur_value_extended >> 8) & 0x7f) as u8,
                            Column::QtAux,
                        );
                    }
                    MemAccessSize::Word => {
                        assert_eq!(cur_value_extended, memory_record.get_value());
                    }
                }
                traces.fill_columns(row_idx, cur_value_extended, Column::ValueA);
            }
            let cur_value: Word = memory_record.get_value().to_le_bytes();
            let prev_value: Word = if is_load {
                cur_value
            } else {
                memory_record
                    .get_prev_value()
                    .expect("Store operation should carry a previous value")
                    .to_le_bytes()
            };

            for (i, (val_cur, val_prev, ts_prev, ram_ts_prev_aux, helper)) in [
                (Ram1ValCur, Ram1ValPrev, Ram1TsPrev, Ram1TsPrevAux, Helper1),
                (Ram2ValCur, Ram2ValPrev, Ram2TsPrev, Ram2TsPrevAux, Helper2),
                (Ram3ValCur, Ram3ValPrev, Ram3TsPrev, Ram3TsPrevAux, Helper3),
                (Ram4ValCur, Ram4ValPrev, Ram4TsPrev, Ram4TsPrevAux, Helper4),
            ]
            .into_iter()
            .take(size)
            .enumerate()
            {
                let prev_access = side_note.rw_mem_check.last_access.insert(
                    byte_address
                        .checked_add(i as u32)
                        .expect("memory access range overflowed back to address zero"),
                    (clk, cur_value[i]),
                );
                let (prev_timestamp, prev_val) = prev_access.unwrap_or((0, 0));
                // If it's LOAD, the vm and the prover need to agree on the previous value
                if is_load {
                    assert_eq!(
                        prev_val,
                        prev_value[i],
                        "memory access value mismatch at address 0x{:x}, prev_timestamp = {}",
                        byte_address.checked_add(i as u32).unwrap(),
                        prev_timestamp,
                    );
                }
                traces.fill_columns(row_idx, cur_value[i], val_cur);
                traces.fill_columns(row_idx, prev_val, val_prev);
                traces.fill_columns(row_idx, prev_timestamp, ts_prev);
                let (ram_ts_prev_aux_word, helper_word) =
                    decr_subtract_with_borrow(clk.to_le_bytes(), prev_timestamp.to_le_bytes());
                traces.fill_columns(row_idx, ram_ts_prev_aux_word, ram_ts_prev_aux);
                traces.fill_columns(row_idx, helper_word, helper);
            }
        }
    }

    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        _program_traces: &ProgramTraces,
        lookup_element: &AllLookupElements,
    ) {
        let lookup_element: &LoadStoreLookupElements = lookup_element.as_ref();
        // This function looks at the main trace and the program trace and fills the logup sums.
        // On each row, values written to the RW memory are added, and values read from the RW memory are subtracted.
        // The initial value is considered to be a write. The final value is considered as a read.
        // A load or a store operation is considered to be a read followed by a write.
        // Each addition or subtraction is computed using `lookup_element` on tuples of the form
        // `[address0, address1, address2, address3, value, counter0, counter1, counter2, counter3]` where
        // - `address{0,1,2,3}` is the accessed memory address in four-limbs each containing one byte
        // - `value` is the one-byte value written to or read from the memory.
        // - `counter{0,1,2,3}` is the timestamp of the memory access. In four-limbs each containing one byte.

        // Subtract and add address1 access components from/to logup sum
        // TODO: make it a loop or four calls
        Self::subtract_add_access::<Ram1Accessed>(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram1ValPrev,
            Ram1TsPrev,
            Ram1ValCur,
            0,
        );
        Self::subtract_add_access::<Ram2Accessed>(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram2ValPrev,
            Ram2TsPrev,
            Ram2ValCur,
            1,
        );
        Self::subtract_add_access::<Ram3_4Accessed>(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram3ValPrev,
            Ram3TsPrev,
            Ram3ValCur,
            2,
        );
        Self::subtract_add_access::<Ram3_4Accessed>(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram4ValPrev,
            Ram4TsPrev,
            Ram4ValCur,
            3,
        );
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &AllLookupElements,
        _config: &ExtensionsConfig,
    ) {
        // Computing ram1_ts_prev_aux = clk - 1 - ram1_ts_prev
        // Helper1 used for borrow handling
        let clk = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let ram1_ts_prev = trace_eval!(trace_eval, Ram1TsPrev);
        let ram1_ts_prev_aux = trace_eval!(trace_eval, Ram1TsPrevAux);
        let helper1 = trace_eval!(trace_eval, Column::Helper1);
        let [ram1_accessed] = Ram1Accessed::eval(trace_eval);
        // ram1_ts_prev_aux_1 + ram1_ts_prev_aux_2 * 256 + 1    + ram1_ts_prev_1 + ram1_ts_prev_2 * 256 = clk_1 + clk_2 * 256 + h1_2・2^16
        // (conditioned on ram1_accessed != 0)
        eval.add_constraint(
            ram1_accessed.clone()
                * (ram1_ts_prev_aux[0].clone()
                    + ram1_ts_prev_aux[1].clone() * BaseField::from(1 << 8)
                    + E::F::one()
                    + ram1_ts_prev[0].clone()
                    + ram1_ts_prev[1].clone() * BaseField::from(1 << 8)
                    - clk[0].clone()
                    - clk[1].clone() * BaseField::from(1 << 8)
                    - helper1[1].clone() * BaseField::from(1 << 16)),
        );
        // ram1_ts_prev_aux_3 + ram1_ts_prev_aux_4 * 256 + h1_2 + ram1_ts_prev_3 + ram1_ts_prev_4 * 256 = clk_3 + clk_4 * 256 + h1_4・2^16
        // (conditioned on ram1_accessed != 0)
        eval.add_constraint(
            ram1_accessed.clone()
                * (ram1_ts_prev_aux[2].clone()
                    + ram1_ts_prev_aux[3].clone() * BaseField::from(1 << 8)
                    + helper1[1].clone()
                    + ram1_ts_prev[2].clone()
                    + ram1_ts_prev[3].clone() * BaseField::from(1 << 8)
                    - clk[2].clone()
                    - clk[3].clone() * BaseField::from(1 << 8)
                    - helper1[3].clone() * BaseField::from(1 << 16)),
        );

        // h1_2・(h1_2 - 1) = 0 (conditioned on ram1_accessed != 0)
        eval.add_constraint(
            helper1[1].clone() * (helper1[1].clone() - E::F::one()) * ram1_accessed.clone(),
        );
        // h1_4 = 0 (conditioned on ram1_accessed != 0)
        eval.add_constraint(helper1[WORD_SIZE - 1].clone() * ram1_accessed.clone());

        // Computing ram2_ts_prev_aux = clk - 1 - ram2_ts_prev
        // Helper2 used for borrow handling
        let ram2_ts_prev = trace_eval!(trace_eval, Ram2TsPrev);
        let ram2_ts_prev_aux = trace_eval!(trace_eval, Ram2TsPrevAux);
        let helper2 = trace_eval!(trace_eval, Column::Helper2);
        let [ram2_accessed] = Ram2Accessed::eval(trace_eval);
        // ram2_ts_prev_aux_1 + ram2_ts_prev_aux_2 * 256 + 1    + ram2_ts_prev_1 + ram2_ts_prev_2 * 256 = clk_1 + clk_2 * 256 + h2_2・2^{16}
        // (conditioned on ram2_accessed != 0)
        eval.add_constraint(
            ram2_accessed.clone()
                * (ram2_ts_prev_aux[0].clone()
                    + ram2_ts_prev_aux[1].clone() * BaseField::from(1 << 8)
                    + E::F::one()
                    + ram2_ts_prev[0].clone()
                    + ram2_ts_prev[1].clone() * BaseField::from(1 << 8)
                    - clk[0].clone()
                    - clk[1].clone() * BaseField::from(1 << 8)
                    - helper2[1].clone() * BaseField::from(1 << 16)),
        );
        // ram2_ts_prev_aux_3 + ram2_ts_prev_aux_4 * 256 + h2_2 + ram2_ts_prev_3 + ram2_ts_prev_4 * 256 = clk_3 + clk_4 * 256 + h2_4・2^{16}
        // (conditioned on ram2_accessed != 0)
        eval.add_constraint(
            ram2_accessed.clone()
                * (ram2_ts_prev_aux[2].clone()
                    + ram2_ts_prev_aux[3].clone() * BaseField::from(1 << 8)
                    + helper2[1].clone()
                    + ram2_ts_prev[2].clone()
                    + ram2_ts_prev[3].clone() * BaseField::from(1 << 8)
                    - clk[2].clone()
                    - clk[3].clone() * BaseField::from(1 << 8)
                    - helper2[3].clone() * BaseField::from(1 << 16)),
        );

        // h2_2・(h2_2 - 1) = 0 (conditioned on ram2_accessed != 0)
        eval.add_constraint(
            helper2[1].clone() * (helper2[1].clone() - E::F::one()) * ram2_accessed.clone(),
        );
        // h2_4 = 0 (conditioned on ram2_accessed != 0)
        eval.add_constraint(helper2[WORD_SIZE - 1].clone() * ram2_accessed.clone());

        // Computing ram3_ts_prev_aux = clk - 1 - ram3_ts_prev
        // Helper3 used for borrow handling
        let ram3_ts_prev = trace_eval!(trace_eval, Ram3TsPrev);
        let ram3_ts_prev_aux = trace_eval!(trace_eval, Ram3TsPrevAux);
        let helper3 = trace_eval!(trace_eval, Column::Helper3);
        let [ram3_4_accessed] = Ram3_4Accessed::eval(trace_eval);
        // ram3_ts_prev_aux_1 + ram3_ts_prev_aux_2 * 256 + 1    + ram3_ts_prev_1 + ram3_ts_prev_2 * 256 = clk_1 + clk_2 * 256 + h3_2・2^{16}
        // (conditioned on ram3_accessed != 0)
        eval.add_constraint(
            ram3_4_accessed.clone()
                * (ram3_ts_prev_aux[0].clone()
                    + ram3_ts_prev_aux[1].clone() * BaseField::from(1 << 8)
                    + E::F::one()
                    + ram3_ts_prev[0].clone()
                    + ram3_ts_prev[1].clone() * BaseField::from(1 << 8)
                    - clk[0].clone()
                    - clk[1].clone() * BaseField::from(1 << 8)
                    - helper3[1].clone() * BaseField::from(1 << 16)),
        );
        // ram3_ts_prev_aux_3 + ram3_ts_prev_aux_4 * 256 + h3_2 + ram3_ts_prev_3 + ram3_ts_prev_4 * 256 = clk_3 + clk_4 * 256 + h3_4・2^{16}
        // (conditioned on ram3_accessed != 0)
        eval.add_constraint(
            ram3_4_accessed.clone()
                * (ram3_ts_prev_aux[2].clone()
                    + ram3_ts_prev_aux[3].clone() * BaseField::from(1 << 8)
                    + helper3[1].clone()
                    + ram3_ts_prev[2].clone()
                    + ram3_ts_prev[3].clone() * BaseField::from(1 << 8)
                    - clk[2].clone()
                    - clk[3].clone() * BaseField::from(1 << 8)
                    - helper3[3].clone() * BaseField::from(1 << 16)),
        );
        // h3_2・(h3_2 - 1) = 0 (conditioned on ram3_accessed != 0)
        eval.add_constraint(
            helper3[1].clone() * (helper3[1].clone() - E::F::one()) * ram3_4_accessed.clone(),
        );
        // h3_4 = 0 (conditioned on ram3_accessed != 0)
        eval.add_constraint(helper3[WORD_SIZE - 1].clone() * ram3_4_accessed.clone());

        // Computing ram4_ts_prev_aux = clk - 1 - ram4_ts_prev
        // Helper4 used for borrow handling
        let ram4_ts_prev = trace_eval!(trace_eval, Ram4TsPrev);
        let ram4_ts_prev_aux = trace_eval!(trace_eval, Ram4TsPrevAux);
        let helper4 = trace_eval!(trace_eval, Column::Helper4);
        eval.add_constraint(
            ram3_4_accessed.clone()
                * (ram4_ts_prev_aux[0].clone()
                    + ram4_ts_prev_aux[1].clone() * BaseField::from(1 << 8)
                    + E::F::one()
                    + ram4_ts_prev[0].clone()
                    + ram4_ts_prev[1].clone() * BaseField::from(1 << 8)
                    - clk[0].clone()
                    - clk[1].clone() * BaseField::from(1 << 8)
                    - helper4[1].clone() * BaseField::from(1 << 16)),
        );
        eval.add_constraint(
            ram3_4_accessed.clone()
                * (ram4_ts_prev_aux[2].clone()
                    + ram4_ts_prev_aux[3].clone() * BaseField::from(1 << 8)
                    + helper4[1].clone()
                    + ram4_ts_prev[2].clone()
                    + ram4_ts_prev[3].clone() * BaseField::from(1 << 8)
                    - clk[2].clone()
                    - clk[3].clone() * BaseField::from(1 << 8)
                    - helper4[3].clone() * BaseField::from(1 << 16)),
        );
        // h4_2・(h4_2 - 1) = 0 (conditioned on ram4_accessed != 0)
        eval.add_constraint(
            helper4[1].clone() * (helper4[1].clone() - E::F::one()) * ram3_4_accessed.clone(),
        );
        // h4_4 = 0 (conditioned on ram4_accessed != 0)
        eval.add_constraint(helper4[WORD_SIZE - 1].clone() * ram3_4_accessed.clone());

        let ram_base_addr = trace_eval!(trace_eval, Column::RamBaseAddr);
        let carry_flag = trace_eval!(trace_eval, Column::CarryFlag);
        let value_b = trace_eval!(trace_eval, Column::ValueB);
        let value_c = trace_eval!(trace_eval, Column::ValueC);
        let value_a = trace_eval!(trace_eval, Column::ValueA);
        let [is_load] = IsLoad::eval(trace_eval);
        // Constrain the value of RamBaseAddr in case of load operations
        // is_load * (ram_base_addr_1 + ram_base_addr_2 * 256 - value_b_1 - value_b_2 * 256 - value_c_1 - value_c_2 * 256 + carry_1 * 2^{16}) = 0
        eval.add_constraint(
            is_load.clone()
                * (ram_base_addr[0].clone() + ram_base_addr[1].clone() * BaseField::from(1 << 8)
                    - value_b[0].clone()
                    - value_b[1].clone() * BaseField::from(1 << 8)
                    - value_c[0].clone()
                    - value_c[1].clone() * BaseField::from(1 << 8)
                    + carry_flag[0].clone() * BaseField::from(1 << 16)),
        );
        // is_load * (ram_base_addr_3 + ram_base_addr_4 * 256 - carry_1 - value_b_3 - value_b_4 * 256 - value_c_3 - value_c_4 * 256 + carry_2 * 2^{16}) = 0
        eval.add_constraint(
            is_load.clone()
                * (ram_base_addr[2].clone() + ram_base_addr[3].clone() * BaseField::from(1 << 8)
                    - carry_flag[0].clone()
                    - value_b[2].clone()
                    - value_b[3].clone() * BaseField::from(1 << 8)
                    - value_c[2].clone()
                    - value_c[3].clone() * BaseField::from(1 << 8)
                    + carry_flag[1].clone() * BaseField::from(1 << 16)),
        );

        // Constrain the value of RamBaseAddr in case of store operations
        let [is_store] = IsTypeS::eval(trace_eval);
        // is_store * (ram_base_addr_1 + ram_base_addr_2 * 256 - value_a_1 - value_a_2 * 256 - value_c_1 - value_c_2 * 256 + carry_1 * 2^{16}) = 0
        eval.add_constraint(
            is_store.clone()
                * (ram_base_addr[0].clone() + ram_base_addr[1].clone() * BaseField::from(1 << 8)
                    - value_a[0].clone()
                    - value_a[1].clone() * BaseField::from(1 << 8)
                    - value_c[0].clone()
                    - value_c[1].clone() * BaseField::from(1 << 8)
                    + carry_flag[0].clone() * BaseField::from(1 << 16)),
        );
        // is_store * (ram_base_addr_3 + ram_base_addr_4 * 256 - carry_1 - value_a_3 - value_a_4 * 256 - value_c_3 - value_c_4 * 256 + carry_2 * 2^{16}) = 0
        eval.add_constraint(
            is_store.clone()
                * (ram_base_addr[2].clone() + ram_base_addr[3].clone() * BaseField::from(1 << 8)
                    - carry_flag[0].clone()
                    - value_a[2].clone()
                    - value_a[3].clone() * BaseField::from(1 << 8)
                    - value_c[2].clone()
                    - value_c[3].clone() * BaseField::from(1 << 8)
                    + carry_flag[1].clone() * BaseField::from(1 << 16)),
        );

        let [ram1_val_prev] = trace_eval!(trace_eval, Ram1ValPrev);
        let [ram2_val_prev] = trace_eval!(trace_eval, Ram2ValPrev);
        let [ram1_val_cur] = trace_eval!(trace_eval, Ram1ValCur);
        let [ram2_val_cur] = trace_eval!(trace_eval, Ram2ValCur);
        // In case of load instruction, the previous and the current values should be the same
        // is_load * (ram1_val_prev + ram2_val_prev * 256 - ram1_val_cur - ram2_val_cur * 256) = 0
        eval.add_constraint(
            is_load.clone()
                * (ram1_val_prev.clone() + ram2_val_prev.clone() * BaseField::from(1 << 8)
                    - ram1_val_cur.clone()
                    - ram2_val_cur.clone() * BaseField::from(1 << 8)),
        );
        let [ram3_val_prev] = trace_eval!(trace_eval, Ram3ValPrev);
        let [ram4_val_prev] = trace_eval!(trace_eval, Ram4ValPrev);
        let [ram3_val_cur] = trace_eval!(trace_eval, Ram3ValCur);
        let [ram4_val_cur] = trace_eval!(trace_eval, Ram4ValCur);
        // is_load * (ram3_val_prev + ram4_val_prev * 256 - ram3_val_cur - ram4_val_cur * 256) = 0
        eval.add_constraint(
            is_load.clone()
                * (ram3_val_prev.clone() + ram4_val_prev.clone() * BaseField::from(1 << 8)
                    - ram3_val_cur.clone()
                    - ram4_val_cur.clone() * BaseField::from(1 << 8)),
        );

        // In case of LW instruction, ValueA should be equal to the loaded values in Ram{1,2,3,4}ValPrev
        let [is_lw] = trace_eval!(trace_eval, IsLw);
        // is_lw * (value_a_1 + value_a_2 * 256 - ram1_val_prev + ram2_val_prev * 256) = 0
        eval.add_constraint(
            is_lw.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - ram1_val_prev.clone()
                    - ram2_val_prev.clone() * BaseField::from(1 << 8)),
        );
        // is_lw * (value_a_3 + value_a_4 * 256 - ram3_val_prev + ram4_val_prev * 256) = 0
        eval.add_constraint(
            is_lw.clone()
                * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)
                    - ram3_val_prev
                    - ram4_val_prev * BaseField::from(1 << 8)),
        );

        // In case of LHU instruction, ValueA[0..=1] should be equal to the loaded values in Ram{1,2}ValPrev
        let [is_lhu] = trace_eval!(trace_eval, IsLhu);
        // is_lhu * (value_a_1 + value_a_2 * 256 - ram1_val_prev + ram2_val_prev * 256) = 0
        eval.add_constraint(
            is_lhu.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - ram1_val_prev.clone()
                    - ram2_val_prev.clone() * BaseField::from(1 << 8)),
        );
        // is_lhu * (value_a_3 + value_a_4 * 256) = 0
        eval.add_constraint(
            is_lhu.clone() * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)),
        );

        // In case of LH instruction, Ram2ValPrev & 0x7f should be stored in QtAux
        // The sign bit of Ram2ValPrev should be (Ram2ValPrev - QtAux) / 128
        let inv_128 = BaseField::from(128).inverse();
        let [is_lh] = trace_eval!(trace_eval, IsLh);
        let [sign_removed] = trace_eval!(trace_eval, Column::QtAux);
        let sign_bit = (ram2_val_prev.clone() - sign_removed.clone()) * inv_128;
        // The sign bit should be zero or one.
        // is_lh * sign_bit * (sign_bit - 1) = 0
        eval.add_constraint(is_lh.clone() * sign_bit.clone() * (sign_bit.clone() - E::F::one()));
        // is_lh * (value_a_1 + value_a_2 * 256 - ram1_val_prev + ram2_val_prev * 256) = 0
        eval.add_constraint(
            is_lh.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - ram1_val_prev.clone()
                    - ram2_val_prev.clone() * BaseField::from(1 << 8)),
        );
        // is_lh * (value_a_3 + value_a_4 * 256 - sign_bit * (2^16 - 1)) = 0
        eval.add_constraint(
            is_lh.clone()
                * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)
                    - sign_bit.clone() * (E::F::from(BaseField::from(1 << 16)) - E::F::one())),
        );

        // In case of LBU instruction ValueA[0] should be equal to the loaded values in Ram1ValPrev
        let [is_lbu] = trace_eval!(trace_eval, IsLbu);
        // is_lbu * (value_a_1 + value_a_2 * 256 - ram1_val_prev) = 0 // No ram2_val_prev
        eval.add_constraint(
            is_lbu.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - ram1_val_prev.clone()),
        );
        // is_lbu * (value_a_3 + value_a_4 * 256) = 0
        eval.add_constraint(
            is_lbu.clone() * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)),
        );

        // In case of LB instruction, Ram1ValPrev & 0x7f should be stored in QtAux
        // The sign bit of Ram1ValPrev should be (Ram1ValPrev - QtAux) / 128
        let [is_lb] = trace_eval!(trace_eval, IsLb);
        let [sign_removed] = trace_eval!(trace_eval, Column::QtAux);
        let sign_bit = (ram1_val_prev.clone() - sign_removed.clone()) * inv_128;
        // The sign bit should be zero or one.
        // is_lb * sign_bit * (sign_bit - 1) = 0
        eval.add_constraint(is_lb.clone() * sign_bit.clone() * (sign_bit.clone() - E::F::one()));
        // is_lb * (value_a_1 + value_a_2 * 256 - ram1_val_prev - sign_bit * 127 * 128) = 0
        eval.add_constraint(
            is_lb.clone()
                * (value_a[0].clone() + value_a[1].clone() * BaseField::from(1 << 8)
                    - ram1_val_prev.clone()
                    - sign_bit.clone()
                        * E::F::from(BaseField::from(255) * BaseField::from(1 << 8))),
        );
        // is_lb * (value_a_3 + value_a_4 * 256 - sign_bit * (2^16 - 1)) = 0
        eval.add_constraint(
            is_lb.clone()
                * (value_a[2].clone() + value_a[3].clone() * BaseField::from(1 << 8)
                    - sign_bit.clone() * (E::F::from(BaseField::from(1 << 16)) - E::F::one())),
        );

        let lookup_elements: &LoadStoreLookupElements = lookup_elements.as_ref();

        Self::constrain_subtract_add_access::<E, Ram1Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            Ram1ValPrev,
            Ram1TsPrev,
            Ram1ValCur,
            0,
        );
        Self::constrain_subtract_add_access::<E, Ram2Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            Ram2ValPrev,
            Ram2TsPrev,
            Ram2ValCur,
            1,
        );
        Self::constrain_subtract_add_access::<E, Ram3_4Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            Ram3ValPrev,
            Ram3TsPrev,
            Ram3ValCur,
            2,
        );
        Self::constrain_subtract_add_access::<E, Ram3_4Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            Ram4ValPrev,
            Ram4TsPrev,
            Ram4ValCur,
            3,
        );
    }
}

impl LoadStoreChip {
    fn subtract_add_access<Accessed: VirtualColumn<1>>(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_prev: Column,
        ts_prev: Column,
        val_cur: Column,
        address_offset: u8,
    ) {
        Self::subtract_access::<Accessed>(
            original_traces,
            lookup_elements,
            logup_trace_gen,
            val_prev,
            ts_prev,
            address_offset,
        );
        Self::add_access::<Accessed>(
            original_traces,
            preprocessed_traces,
            lookup_elements,
            logup_trace_gen,
            val_cur,
            address_offset,
        );
    }

    fn constrain_subtract_add_access<E: EvalAtRow, Accessed: VirtualColumn<1>>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_prev: Column,
        ts_prev: Column,
        val_cur: Column,
        address_offset: u8,
    ) {
        Self::constrain_subtract_address::<E, Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            val_prev,
            ts_prev,
            address_offset,
        );
        Self::constrain_add_access::<E, Accessed>(
            eval,
            trace_eval,
            lookup_elements,
            val_cur,
            address_offset,
        );
    }

    fn subtract_access<Accessed: VirtualColumn<1>>(
        original_traces: &FinalizedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_prev: Column,
        ts_prev: Column,
        address_offset: u8,
    ) {
        let [val_prev] = original_traces.get_base_column(val_prev);
        let ts_prev = original_traces.get_base_column::<WORD_SIZE>(ts_prev);
        let base_address = original_traces.get_base_column::<WORD_SIZE>(Column::RamBaseAddr);
        // Subtract previous tuple
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            // The least significant byte of the address is base_address[0] + address_offset.
            // Adding an offset without carry is correct because of memory alignment.
            let addr_low = base_address[0].data[vec_row]
                + PackedBaseField::broadcast(BaseField::from(address_offset as u32))
                + base_address[1].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            let addr_high = base_address[2].data[vec_row]
                + base_address[3].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            tuple.push(addr_low);
            tuple.push(addr_high);

            tuple.push(val_prev.data[vec_row]);

            let ts_low = ts_prev[0].data[vec_row]
                + ts_prev[1].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            let ts_high = ts_prev[2].data[vec_row]
                + ts_prev[3].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            tuple.push(ts_low);
            tuple.push(ts_high);
            assert_eq!(tuple.len(), 2 * WORD_SIZE_HALVED + 1);
            let [accessed] = Accessed::read_from_finalized_traces(original_traces, vec_row);
            logup_col_gen.write_frac(
                vec_row,
                (-accessed).into(),
                lookup_elements.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_subtract_address<E: EvalAtRow, Accessed: VirtualColumn<1>>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_prev: Column,
        ts_prev: Column,
        address_offset: u8,
    ) {
        let [val_prev] = trace_eval.column_eval(val_prev);
        let ts_prev = trace_eval.column_eval::<WORD_SIZE>(ts_prev);
        let [accessed] = Accessed::eval(trace_eval);
        let base_address = trace_eval!(trace_eval, Column::RamBaseAddr);
        let mut tuple = vec![];
        // The least significant byte of the address is base_address[0] + address_offset
        // Adding an offset without carry is correct because of memory alignment.
        let addr_low = base_address[0].clone()
            + E::F::from(BaseField::from(address_offset as u32))
            + base_address[1].clone() * E::F::from((1 << 8).into());
        let addr_high =
            base_address[2].clone() + base_address[3].clone() * E::F::from((1 << 8).into());
        tuple.push(addr_low);
        tuple.push(addr_high);

        tuple.push(val_prev);

        let ts_low = ts_prev[0].clone() + ts_prev[1].clone() * E::F::from((1 << 8).into());
        let ts_high = ts_prev[2].clone() + ts_prev[3].clone() * E::F::from((1 << 8).into());
        tuple.push(ts_low);
        tuple.push(ts_high);

        assert_eq!(tuple.len(), 2 * WORD_SIZE_HALVED + 1);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-accessed).into(),
            &tuple,
        ));
    }

    fn add_access<Accessed: VirtualColumn<1>>(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_cur: Column,
        address_offset: u8,
    ) {
        let [val_cur] = original_traces.get_base_column(val_cur);
        let base_address = original_traces.get_base_column::<WORD_SIZE>(Column::RamBaseAddr);
        // Add current tuple
        let clk =
            preprocessed_traces.get_preprocessed_base_column::<WORD_SIZE>(PreprocessedColumn::Clk);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            // The least significant byte of the address is base_address[0] + address_offset
            // Adding an offset without carry is correct because of memory alignment.
            let addr_low = base_address[0].data[vec_row]
                + PackedBaseField::broadcast(BaseField::from(address_offset as u32))
                + base_address[1].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            let addr_high = base_address[2].data[vec_row]
                + base_address[3].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            tuple.push(addr_low);
            tuple.push(addr_high);

            tuple.push(val_cur.data[vec_row]);

            let clk_low = clk[0].data[vec_row]
                + clk[1].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            let clk_high = clk[2].data[vec_row]
                + clk[3].data[vec_row] * PackedBaseField::broadcast((1 << 8).into());
            tuple.push(clk_low);
            tuple.push(clk_high);

            assert_eq!(tuple.len(), 2 * WORD_SIZE_HALVED + 1);
            let [accessed] = Accessed::read_from_finalized_traces(original_traces, vec_row);
            logup_col_gen.write_frac(
                vec_row,
                accessed.into(),
                lookup_elements.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_add_access<E: EvalAtRow, Accessed: VirtualColumn<1>>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_cur: Column,
        address_offset: u8,
    ) {
        let [val_cur] = trace_eval.column_eval(val_cur);
        let [accessed] = Accessed::eval(trace_eval);
        let base_address = trace_eval!(trace_eval, Column::RamBaseAddr);
        let clk = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let mut tuple = vec![];
        // The least significant byte of the address is base_address[0] + address_offset
        // Adding an offset without carry is correct because of memory alignment.
        let addr_low = base_address[0].clone()
            + E::F::from(BaseField::from(address_offset as u32))
            + base_address[1].clone() * E::F::from((1 << 8).into());
        let addr_high =
            base_address[2].clone() + base_address[3].clone() * E::F::from((1 << 8).into());
        tuple.push(addr_low);
        tuple.push(addr_high);

        tuple.push(val_cur);

        let clk_low = clk[0].clone() + clk[1].clone() * E::F::from((1 << 8).into());
        let clk_high = clk[2].clone() + clk[3].clone() * E::F::from((1 << 8).into());
        tuple.push(clk_low);
        tuple.push(clk_high);
        assert_eq!(tuple.len(), 2 * WORD_SIZE_HALVED + 1);

        eval.add_to_relation(RelationEntry::new(lookup_elements, accessed.into(), &tuple));
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{
            range_check::{
                range128::Range128Chip, range16::Range16Chip, range256::Range256Chip,
                range32::Range32Chip, range8::Range8Chip,
            },
            AddChip, BeqChip, BitOpChip, CpuChip, DecodingCheckChip, RegisterMemCheckChip, SllChip,
        },
        machine::Machine,
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
        },
    };

    use super::*;
    use nexus_vm::{
        emulator::InternalView,
        riscv::{BasicBlock, BuiltinOpcode, Instruction, Opcode},
        trace::k_trace_direct,
    };

    const LOG_SIZE: u32 = PreprocessedTraces::MIN_LOG_SIZE;

    fn setup_basic_block_ir() -> Vec<BasicBlock> {
        let basic_block = BasicBlock::new(vec![
            // First we create a usable address. heap start: 528392, heap end: 8917000
            // Aiming to create 0x81008
            // Set x0 = 0 (default constant), x1 = 1
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 1, 0, 1),
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SLLI), 1, 1, 19),
            // here x1 should be 0x80000
            // Adding x1 to x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADD), 2, 1, 2),
            // Now x2 should be 0x81008
            // Seeting x3 to be 128
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 3, 0, 128),
            // Storing a byte *x3 = 128 to memory address *x2
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SB), 2, 3, 0),
            // Storing two-bytes *x3 = 128 to memory address *x2 + 10
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SH), 2, 3, 10),
            // Storing four-bytes *x3 = 128 to memory address *x2 + 20
            Instruction::new_ir(Opcode::from(BuiltinOpcode::SW), 2, 3, 20),
            // Load a byte from memory address *x2 to x6, expecting 0xffffff80 (sign-extended)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LB), 6, 2, 0),
            // Add 128 to x6, expecting 0 in x6
            Instruction::new_ir(Opcode::from(BuiltinOpcode::ADDI), 6, 6, 128),
            // BEQ x6, x0, 8 (should branch as x6 == x0 == 0)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 6, 0, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Load a byte from memory address *x2 to x6, expecting 128 (zero-extened)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LBU), 6, 2, 0),
            // BEQ x6, x3, 8 (should branch as x6 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 6, 3, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Load two bytes from memory address *x2 + 10 to x6, expecting 128 (sign-extended)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LH), 6, 2, 10),
            // BEQ x6, x3, 8 (should branch as x6 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 6, 3, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Load two bytes from memory address *x2 + 10 to x6, expecting 128 (zero-extended)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LHU), 6, 2, 10),
            // BEQ x6, x3, 8 (should branch as x6 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 6, 3, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
            // Load four bytes from memory address *x2 + 20 to x6, expecting 128
            Instruction::new_ir(Opcode::from(BuiltinOpcode::LW), 6, 2, 20),
            // BEQ x6, x3, 8 (should branch as x6 == x3)
            Instruction::new_ir(Opcode::from(BuiltinOpcode::BEQ), 6, 3, 8),
            // Unimpl instructions to fill the gap (trigger error when executed)
            Instruction::unimpl(),
        ]);
        vec![basic_block]
    }

    #[test]
    fn test_k_trace_constrained_store_instructions() {
        type Chips = (
            CpuChip,
            DecodingCheckChip,
            AddChip,
            BeqChip,
            SllChip,
            LoadStoreChip,
            // `prove` call includes default extensions that require lookup elements.
            RegisterMemCheckChip,
            Range8Chip,
            Range16Chip,
            Range32Chip,
            Range128Chip,
            Range256Chip,
            BitOpChip,
        );
        let basic_block = setup_basic_block_ir();
        let k = 1;

        // Get traces from VM K-Trace interface
        let (view, vm_traces) = k_trace_direct(&basic_block, k).expect("Failed to create trace");

        // Trace circuit
        let mut traces = TracesBuilder::new(LOG_SIZE);
        let program_steps = iter_program_steps(&vm_traces, traces.num_rows());
        let program_trace = ProgramTracesBuilder::dummy(LOG_SIZE);
        let mut side_note = SideNote::new(&program_trace, &view);

        for (row_idx, program_step) in program_steps.enumerate() {
            Chips::fill_main_trace(
                &mut traces,
                row_idx,
                &program_step,
                &mut side_note,
                &ExtensionsConfig::default(),
            );
        }

        // Assert results of loads
        let load_vals = traces
            .column(7, Column::ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(load_vals);
        assert_eq!(output, 0xffffff80);

        let load_vals = traces
            .column(10, Column::ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(load_vals);
        assert_eq!(output, 128);

        let load_vals = traces
            .column(12, Column::ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(load_vals);
        assert_eq!(output, 128);

        let load_vals = traces
            .column(14, Column::ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(load_vals);
        assert_eq!(output, 128);

        let load_vals = traces
            .column(16, Column::ValueA)
            .map(|v| u8::try_from(v.0).expect("limb value out of bounds"));
        let output = u32::from_le_bytes(load_vals);
        assert_eq!(output, 128);

        assert_chip::<Chips>(traces, Some(program_trace.finalize()));
        let proof = Machine::<Chips>::prove(&vm_traces, &view).unwrap();
        // verify to enforce logup sum being zero
        Machine::<Chips>::verify(
            proof,
            view.get_program_memory(),
            view.view_associated_data().as_deref().unwrap_or_default(),
            view.get_initial_memory(),
            view.get_exit_code(),
            view.get_public_output(),
        )
        .unwrap();
    }
}
