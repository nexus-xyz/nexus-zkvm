use nexus_vm::{memory::MemAccessSize, riscv::BuiltinOpcode, WORD_SIZE};
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{logup::LogupTraceGenerator, EvalAtRow, Relation, RelationEntry},
    core::{
        backend::simd::m31::{PackedBaseField, LOG_N_LANES},
        fields::m31::{self, BaseField},
    },
};

use crate::{
    chips::memory_check::decr_subtract_with_borrow,
    column::{
        Column::{
            self, Helper1, Helper2, Helper3, Helper4, IsLb, IsLbu, IsLh, IsLhu, IsLw, IsSb, IsSh,
            IsSw, Ram1Accessed, Ram1TsPrev, Ram1TsPrevAux, Ram1ValCur, Ram1ValPrev, Ram2Accessed,
            Ram2TsPrev, Ram2TsPrevAux, Ram2ValCur, Ram2ValPrev, Ram3Accessed, Ram3TsPrev,
            Ram3TsPrevAux, Ram3ValCur, Ram3ValPrev, Ram4Accessed, Ram4TsPrev, Ram4TsPrevAux,
            Ram4ValCur, Ram4ValPrev,
        },
        PreprocessedColumn, ProgramColumn,
    },
    components::AllLookupElements,
    trace::{
        eval::{preprocessed_trace_eval, program_trace_eval, trace_eval},
        program_trace::ProgramTraces,
        sidenote::SideNote,
        FinalizedTraces, PreprocessedTraces, ProgramStep, TracesBuilder, Word,
    },
    traits::MachineChip,
};

use super::add::add_with_carries;

// Support SB, SH, SW, LB, LH and LW opcodes
pub struct LoadStoreChip;

const LOOKUP_TUPLE_SIZE: usize = 2 * WORD_SIZE + 1;
stwo_prover::relation!(LoadStoreLookupElements, LOOKUP_TUPLE_SIZE);

impl MachineChip for LoadStoreChip {
    fn draw_lookup_elements(
        all_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        all_elements.insert(LoadStoreLookupElements::draw(channel));
    }

    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
    ) {
        Self::fill_main_trace_step(traces, row_idx, vm_step, side_note);
        if (row_idx + 1) == traces.num_rows() {
            Self::fill_main_trace_finish(traces, row_idx, vm_step, side_note);
        }
    }

    fn fill_interaction_trace(
        logup_trace_gen: &mut LogupTraceGenerator,
        original_traces: &FinalizedTraces,
        preprocessed_trace: &PreprocessedTraces,
        program_traces: &ProgramTraces,
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

        // Add initial values to logup sum
        Self::add_initial_values(
            original_traces,
            program_traces,
            lookup_element,
            logup_trace_gen,
        );

        // Subtract and add address1 access components from/to logup sum
        // TODO: make it a loop or four calls
        Self::subtract_add_access(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram1ValPrev,
            Ram1TsPrev,
            Ram1ValCur,
            Ram1Accessed,
            0,
        );
        Self::subtract_add_access(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram2ValPrev,
            Ram2TsPrev,
            Ram2ValCur,
            Ram2Accessed,
            1,
        );
        Self::subtract_add_access(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram3ValPrev,
            Ram3TsPrev,
            Ram3ValCur,
            Ram3Accessed,
            2,
        );
        Self::subtract_add_access(
            original_traces,
            preprocessed_trace,
            lookup_element,
            logup_trace_gen,
            Ram4ValPrev,
            Ram4TsPrev,
            Ram4ValCur,
            Ram4Accessed,
            3,
        );

        // Subtract final values from logup sum
        Self::subtract_final_values(original_traces, lookup_element, logup_trace_gen);
    }

    fn add_constraints<E: stwo_prover::constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &AllLookupElements,
    ) {
        let [is_sb] = trace_eval!(trace_eval, IsSb);
        let [is_sh] = trace_eval!(trace_eval, IsSh);
        let [is_sw] = trace_eval!(trace_eval, IsSw);
        let [is_lb] = trace_eval!(trace_eval, IsLb);
        let [is_lh] = trace_eval!(trace_eval, IsLh);
        let [is_lbu] = trace_eval!(trace_eval, IsLbu);
        let [is_lhu] = trace_eval!(trace_eval, IsLhu);
        let [is_lw] = trace_eval!(trace_eval, IsLw);
        // Constrain the value of Ram1Accessed to be true when load or store happens. All of them access at least one byte of RAM.
        let [ram1_accessed] = trace_eval!(trace_eval, Ram1Accessed);
        eval.add_constraint(
            (is_sb.clone()
                + is_sh.clone()
                + is_sw.clone()
                + is_lb.clone()
                + is_lh.clone()
                + is_lbu.clone()
                + is_lhu.clone()
                + is_lw.clone())
                * (E::F::one() - ram1_accessed.clone()),
        );
        // Constrain the value of Ram2Accessed to be true for multi-byte memory access; false for single-byte memory access.
        let [ram2_accessed] = trace_eval!(trace_eval, Ram2Accessed);
        eval.add_constraint(
            (is_sb.clone() + is_lb.clone() + is_lbu.clone()) * ram2_accessed.clone(),
        );
        eval.add_constraint(
            (is_sh.clone() + is_sw.clone() + is_lh.clone() + is_lhu.clone() + is_lw.clone())
                * (E::F::one() - ram2_accessed.clone()),
        );
        // Constrain the value of Ram3Accessed to be true for word memory access; false for half-word and single-byte memory access.
        let [ram3_accessed] = trace_eval!(trace_eval, Ram3Accessed);
        eval.add_constraint(
            (is_sb.clone()
                + is_sh.clone()
                + is_lb.clone()
                + is_lh.clone()
                + is_lhu.clone()
                + is_lbu.clone())
                * ram3_accessed.clone(),
        );
        eval.add_constraint(
            (is_sw.clone() + is_lw.clone()) * (E::F::one() - ram3_accessed.clone()),
        );
        // Constrain the value of Ram4Accessed to be true for word memory access; false for half-word and single-byte memory access.
        let [ram4_accessed] = trace_eval!(trace_eval, Ram4Accessed);
        eval.add_constraint(
            (is_sb + is_sh + is_lb + is_lbu + is_lh + is_lhu) * ram4_accessed.clone(),
        );
        eval.add_constraint((is_sw + is_lw) * (E::F::one() - ram4_accessed.clone()));

        // Constraints for RAM vs public I/O consistency
        let [initial_memory_flag] =
            program_trace_eval!(trace_eval, ProgramColumn::PublicInitialMemoryFlag);
        let [public_output_flag] = program_trace_eval!(trace_eval, ProgramColumn::PublicOutputFlag);
        let ram_init_final_addr = trace_eval!(trace_eval, Column::RamInitFinalAddr);
        let public_ram_addr = program_trace_eval!(trace_eval, ProgramColumn::PublicRamAddr);
        // (initial_memory_flag + public_output_flag) ・(ram_init_final_addr_1 - public_ram_addr_1) = 0
        // (initial_memory_flag + public_output_flag) ・(ram_init_final_addr_2 - public_ram_addr_2) = 0
        // (initial_memory_flag + public_output_flag) ・(ram_init_final_addr_3 - public_ram_addr_3) = 0
        // (initial_memory_flag + public_output_flag) ・(ram_init_final_addr_4 - public_ram_addr_4) = 0
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                (initial_memory_flag.clone() + public_output_flag.clone())
                    * (ram_init_final_addr[i].clone() - public_ram_addr[i].clone()),
            );
        }
        // public_output_flag ・(ram_final_value - public_output_value) = 0
        let [ram_final_value] = trace_eval!(trace_eval, Column::RamFinalValue);
        let [public_output_value] =
            program_trace_eval!(trace_eval, ProgramColumn::PublicOutputValue);
        eval.add_constraint(
            public_output_flag.clone() * (ram_final_value.clone() - public_output_value.clone()),
        );

        // Computing ram1_ts_prev_aux = clk - 1 - ram1_ts_prev
        // Helper1 used for borrow handling
        let clk = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let ram1_ts_prev = trace_eval!(trace_eval, Ram1TsPrev);
        let ram1_ts_prev_aux = trace_eval!(trace_eval, Ram1TsPrevAux);
        let helper1 = trace_eval!(trace_eval, Column::Helper1);
        // ram1_ts_prev_aux_1 + 1    + ram1_ts_prev_1 = clk_1 + h1_1・2^8 (conditioned on ram1_accessed != 0)
        eval.add_constraint(
            ram1_accessed.clone()
                * (ram1_ts_prev_aux[0].clone() + E::F::one() + ram1_ts_prev[0].clone()
                    - clk[0].clone()
                    - helper1[0].clone() * BaseField::from(1 << 8)),
        );
        // ram1_ts_prev_aux_2 + h1_1 + ram1_ts_prev_2 = clk_2 + h1_2・2^8 (conditioned on ram1_accessed != 0)
        // ram1_ts_prev_aux_3 + h1_2 + ram1_ts_prev_3 = clk_3 + h1_3・2^8 (conditioned on ram1_accessed != 0)
        // ram1_ts_prev_aux_4 + h1_3 + ram1_ts_prev_4 = clk_4 + h1_4・2^8 (conditioned on ram1_accessed != 0)
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                ram1_accessed.clone()
                    * (ram1_ts_prev_aux[i].clone()
                        + helper1[i - 1].clone()
                        + ram1_ts_prev[i].clone()
                        - clk[i].clone()
                        - helper1[i].clone() * BaseField::from(1 << 8)),
            );
        }
        // h1_1・(h1_1 - 1) = 0; h1_2・(h1_2 - 1) = 0 (conditioned on ram1_accessed != 0)
        // h1_3・(h1_3 - 1) = 0; h1_4 = 0 (conditioned on ram1_accessed != 0)
        for helper_limb in helper1.iter().take(WORD_SIZE - 1) {
            eval.add_constraint(
                helper_limb.clone() * (helper_limb.clone() - E::F::one()) * ram1_accessed.clone(),
            );
        }
        eval.add_constraint(helper1[WORD_SIZE - 1].clone() * ram1_accessed.clone());

        // Computing ram2_ts_prev_aux = clk - 1 - ram2_ts_prev
        // Helper2 used for borrow handling
        let ram2_ts_prev = trace_eval!(trace_eval, Ram2TsPrev);
        let ram2_ts_prev_aux = trace_eval!(trace_eval, Ram2TsPrevAux);
        let helper2 = trace_eval!(trace_eval, Column::Helper2);
        // ram2_ts_prev_aux_1 + 1    + ram2_ts_prev_1 = clk_1 + h2_1・2^8 (conditioned on ram2_accessed != 0)
        eval.add_constraint(
            ram2_accessed.clone()
                * (ram2_ts_prev_aux[0].clone() + E::F::one() + ram2_ts_prev[0].clone()
                    - clk[0].clone()
                    - helper2[0].clone() * BaseField::from(1 << 8)),
        );
        // ram2_ts_prev_aux_2 + h2_1 + ram2_ts_prev_2 = clk_2 + h2_2・2^8 (conditioned on ram2_accessed != 0)
        // ram2_ts_prev_aux_3 + h2_2 + ram2_ts_prev_3 = clk_3 + h2_3・2^8 (conditioned on ram2_accessed != 0)
        // ram2_ts_prev_aux_4 + h2_3 + ram2_ts_prev_4 = clk_4 + h2_4・2^8 (conditioned on ram2_accessed != 0)
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                ram2_accessed.clone()
                    * (ram2_ts_prev_aux[i].clone()
                        + helper2[i - 1].clone()
                        + ram2_ts_prev[i].clone()
                        - clk[i].clone()
                        - helper2[i].clone() * BaseField::from(1 << 8)),
            );
        }
        // h2_1・(h2_1 - 1) = 0; h2_2・(h2_2 - 1) = 0 (conditioned on ram2_accessed != 0)
        // h2_3・(h2_3 - 1) = 0; h2_4 = 0 (conditioned on ram2_accessed != 0)
        for helper2_limb in helper2.iter().take(WORD_SIZE - 1) {
            eval.add_constraint(
                helper2_limb.clone() * (helper2_limb.clone() - E::F::one()) * ram2_accessed.clone(),
            );
        }
        eval.add_constraint(helper2[WORD_SIZE - 1].clone() * ram2_accessed.clone());

        // Computing ram3_ts_prev_aux = clk - 1 - ram3_ts_prev
        // Helper3 used for borrow handling
        let ram3_ts_prev = trace_eval!(trace_eval, Ram3TsPrev);
        let ram3_ts_prev_aux = trace_eval!(trace_eval, Ram3TsPrevAux);
        let helper3 = trace_eval!(trace_eval, Column::Helper3);
        // ram3_ts_prev_aux_1 + 1    + ram3_ts_prev_1 = clk_1 + h3_1・2^8 (conditioned on ram3_accessed != 0)
        eval.add_constraint(
            ram3_accessed.clone()
                * (ram3_ts_prev_aux[0].clone() + E::F::one() + ram3_ts_prev[0].clone()
                    - clk[0].clone()
                    - helper3[0].clone() * BaseField::from(1 << 8)),
        );
        // ram3_ts_prev_aux_2 + h3_1 + ram3_ts_prev_2 = clk_2 + h3_2・2^8 (conditioned on ram3_accessed != 0)
        // ram3_ts_prev_aux_3 + h3_2 + ram3_ts_prev_3 = clk_3 + h3_3・2^8 (conditioned on ram3_accessed != 0)
        // ram3_ts_prev_aux_4 + h3_3 + ram3_ts_prev_4 = clk_4 + h3_4・2^8 (conditioned on ram3_accessed != 0)
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                ram3_accessed.clone()
                    * (ram3_ts_prev_aux[i].clone()
                        + helper3[i - 1].clone()
                        + ram3_ts_prev[i].clone()
                        - clk[i].clone()
                        - helper3[i].clone() * BaseField::from(1 << 8)),
            );
        }
        // h3_1・(h3_1 - 1) = 0; h3_2・(h3_2 - 1) = 0 (conditioned on ram3_accessed != 0)
        // h3_3・(h3_3 - 1) = 0; h3_4 = 0 (conditioned on ram3_accessed != 0)
        for helper3_limb in helper3.iter().take(WORD_SIZE - 1) {
            eval.add_constraint(
                helper3_limb.clone() * (helper3_limb.clone() - E::F::one()) * ram3_accessed.clone(),
            );
        }
        eval.add_constraint(helper3[WORD_SIZE - 1].clone() * ram3_accessed.clone());

        // Computing ram4_ts_prev_aux = clk - 1 - ram4_ts_prev
        // Helper4 used for borrow handling
        let ram4_ts_prev = trace_eval!(trace_eval, Ram4TsPrev);
        let ram4_ts_prev_aux = trace_eval!(trace_eval, Ram4TsPrevAux);
        let helper4 = trace_eval!(trace_eval, Column::Helper4);
        eval.add_constraint(
            ram4_accessed.clone()
                * (ram4_ts_prev_aux[0].clone() + E::F::one() + ram4_ts_prev[0].clone()
                    - clk[0].clone()
                    - helper4[0].clone() * BaseField::from(1 << 8)),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                ram4_accessed.clone()
                    * (ram4_ts_prev_aux[i].clone()
                        + helper4[i - 1].clone()
                        + ram4_ts_prev[i].clone()
                        - clk[i].clone()
                        - helper4[i].clone() * BaseField::from(1 << 8)),
            );
        }
        // h4_1・(h4_1 - 1) = 0; h4_2・(h4_2 - 1) = 0 (conditioned on ram4_accessed != 0)
        // h4_3・(h4_3 - 1) = 0; h4_4 = 0 (conditioned on ram4_accessed != 0)
        for helper_4_limb in helper4.iter().take(WORD_SIZE - 1) {
            eval.add_constraint(
                helper_4_limb.clone()
                    * (helper_4_limb.clone() - E::F::one())
                    * ram4_accessed.clone(),
            );
        }
        eval.add_constraint(helper4[WORD_SIZE - 1].clone() * ram4_accessed.clone());

        let lookup_elements: &LoadStoreLookupElements = lookup_elements.as_ref();

        Self::constrain_add_initial_values(eval, trace_eval, lookup_elements);
        Self::constrain_subtract_add_access(
            eval,
            trace_eval,
            lookup_elements,
            Ram1ValPrev,
            Ram1TsPrev,
            Ram1ValCur,
            Ram1Accessed,
            0,
        );
        Self::constrain_subtract_add_access(
            eval,
            trace_eval,
            lookup_elements,
            Ram2ValPrev,
            Ram2TsPrev,
            Ram2ValCur,
            Ram2Accessed,
            1,
        );
        Self::constrain_subtract_add_access(
            eval,
            trace_eval,
            lookup_elements,
            Ram3ValPrev,
            Ram3TsPrev,
            Ram3ValCur,
            Ram3Accessed,
            2,
        );
        Self::constrain_subtract_add_access(
            eval,
            trace_eval,
            lookup_elements,
            Ram4ValPrev,
            Ram4TsPrev,
            Ram4ValCur,
            Ram4Accessed,
            3,
        );
        Self::constrain_final_values(eval, trace_eval, lookup_elements);
    }
}

impl LoadStoreChip {
    fn fill_main_trace_step(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
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
        traces.fill_columns(row_idx, value_a, Column::ValueAEffective);
        let value_b = vm_step.get_value_b();
        let (offset, effective_bits) = vm_step.get_value_c();
        assert_eq!(effective_bits, 12);
        let (ram_base_address, carry_bits) = if is_load {
            add_with_carries(value_b, offset)
        } else {
            add_with_carries(value_a, offset)
        };
        traces.fill_columns(row_idx, ram_base_address, Column::RamBaseAddr);
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
                    (memory_record.get_prev_value().unwrap() as usize) < { 1usize } << (size * 8),
                    "a memory operation contains a too big prev value"
                );
            }
            assert!(
                (memory_record.get_value() as usize) < { 1usize } << (size * 8),
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
                    }
                    MemAccessSize::HalfWord => {
                        assert_eq!(
                            cur_value_extended & 0xffff,
                            memory_record.get_value() & 0xffff
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

            for (i, (val_cur, val_prev, ts_prev, accessed, ram_ts_prev_aux, helper)) in [
                (
                    Ram1ValCur,
                    Ram1ValPrev,
                    Ram1TsPrev,
                    Ram1Accessed,
                    Ram1TsPrevAux,
                    Helper1,
                ),
                (
                    Ram2ValCur,
                    Ram2ValPrev,
                    Ram2TsPrev,
                    Ram2Accessed,
                    Ram2TsPrevAux,
                    Helper2,
                ),
                (
                    Ram3ValCur,
                    Ram3ValPrev,
                    Ram3TsPrev,
                    Ram3Accessed,
                    Ram3TsPrevAux,
                    Helper3,
                ),
                (
                    Ram4ValCur,
                    Ram4ValPrev,
                    Ram4TsPrev,
                    Ram4Accessed,
                    Ram4TsPrevAux,
                    Helper4,
                ),
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
                traces.fill_columns(row_idx, true, accessed);
                let (ram_ts_prev_aux_word, helper_word) =
                    decr_subtract_with_borrow(clk.to_le_bytes(), prev_timestamp.to_le_bytes());
                traces.fill_columns(row_idx, ram_ts_prev_aux_word, ram_ts_prev_aux);
                traces.fill_columns(row_idx, helper_word, helper);
            }
        }
    }
    /// fill in trace elements for initial and final states of the touched addresses
    ///
    /// Only to be called on the last row after the usual trace filling.
    fn fill_main_trace_finish(
        traces: &mut TracesBuilder,
        row_idx: usize,
        _vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
    ) {
        assert_eq!(row_idx + 1, traces.num_rows());

        // side_note.rw_mem_check.last_access contains the last access time and value for every address under RW memory checking
        for (row_idx, (address, (last_access, last_value))) in
            side_note.rw_mem_check.last_access.iter().enumerate()
        {
            traces.fill_columns(row_idx, *address, Column::RamInitFinalAddr);
            traces.fill_columns(row_idx, true, Column::RamInitFinalFlag);
            assert!(
                *last_access < m31::P,
                "Access counter overflowed BaseField, redesign needed"
            );
            traces.fill_columns(row_idx, *last_access, Column::RamFinalCounter);
            traces.fill_columns(row_idx, *last_value, Column::RamFinalValue);

            // remove public output entry if it exists
            if let Some(out_value) = side_note.rw_mem_check.public_output.remove(address) {
                assert_eq!(out_value, *last_value, "program output mismatch, expected {out_value} at addr {address}, got {last_value}");
            }
        }
        if !side_note.rw_mem_check.public_output.is_empty() {
            panic!(
                "public output memory wasn't written by the prover {:?}",
                side_note.rw_mem_check.public_output
            )
        }
    }

    /// Fills the interaction trace for adding the initial content of the RW memory.
    ///
    /// - `RamInitFinalFlag` indicates whether a row should contain an initial byte of the RW memory.
    /// - `RamInitFinalAddr` contains the address of the RW memory
    /// - `InitialMemoryFlag` indicates whether a row should contain a byte of the publicly known initial RW memory, flag being zero means the initial value is zero.
    /// - `InitialMemoryValue` contains the initial value of the RW memory, used if `InitialMemoryFlag` is true.
    ///
    /// The counter of the initial value is always zero.
    fn add_initial_values(
        original_traces: &FinalizedTraces,
        program_traces: &ProgramTraces,
        lookup_element: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
    ) {
        let [ram_init_final_flag] = original_traces.get_base_column(Column::RamInitFinalFlag);
        let ram_init_final_addr =
            original_traces.get_base_column::<WORD_SIZE>(Column::RamInitFinalAddr);
        let [initial_memory_flag] =
            program_traces.get_base_column(ProgramColumn::PublicInitialMemoryFlag);
        let [initial_memory_value] =
            program_traces.get_base_column(ProgramColumn::PublicInitialMemoryValue);
        let mut logup_col_gen = logup_trace_gen.new_col();
        // Add (address, value, 0)
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for address_byte in ram_init_final_addr.iter() {
                tuple.push(address_byte.data[vec_row]);
            }
            tuple.push(initial_memory_flag.data[vec_row] * initial_memory_value.data[vec_row]); // Is this too much degree?
                                                                                                // The counter is zero
            tuple.extend_from_slice(&[PackedBaseField::zero(); WORD_SIZE]);
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let denom = lookup_element.combine(&tuple);
            let numerator = ram_init_final_flag.data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_add_initial_values<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
    ) {
        let [ram_init_final_flag] = trace_eval!(trace_eval, Column::RamInitFinalFlag);
        let ram_init_final_addr = trace_eval!(trace_eval, Column::RamInitFinalAddr);
        let [initial_memory_flag] =
            program_trace_eval!(trace_eval, ProgramColumn::PublicInitialMemoryFlag);
        let [initial_memory_value] =
            program_trace_eval!(trace_eval, ProgramColumn::PublicInitialMemoryValue);
        let mut tuple = vec![];
        for address_byte in ram_init_final_addr.iter() {
            tuple.push(address_byte.clone());
        }
        tuple.push(initial_memory_flag * initial_memory_value); // Is this too much degree?
                                                                // The counter is zero
        for _ in 0..WORD_SIZE {
            tuple.extend_from_slice(&[E::F::zero()]);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
        let numerator = ram_init_final_flag;

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            numerator.into(),
            &tuple,
        ));
    }

    fn subtract_add_access(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_prev: Column,
        ts_prev: Column,
        val_cur: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        Self::subtract_access(
            original_traces,
            lookup_elements,
            logup_trace_gen,
            val_prev,
            ts_prev,
            accessed,
            address_offset,
        );
        Self::add_access(
            original_traces,
            preprocessed_traces,
            lookup_elements,
            logup_trace_gen,
            val_cur,
            accessed,
            address_offset,
        );
    }

    fn constrain_subtract_add_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_prev: Column,
        ts_prev: Column,
        val_cur: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        Self::constrain_subtract_address(
            eval,
            trace_eval,
            lookup_elements,
            val_prev,
            ts_prev,
            accessed,
            address_offset,
        );
        Self::constrain_add_access(
            eval,
            trace_eval,
            lookup_elements,
            val_cur,
            accessed,
            address_offset,
        );
    }

    fn subtract_access(
        original_traces: &FinalizedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_prev: Column,
        ts_prev: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        let [val_prev] = original_traces.get_base_column(val_prev);
        let ts_prev = original_traces.get_base_column::<WORD_SIZE>(ts_prev);
        let [accessed] = original_traces.get_base_column(accessed);
        let base_address = original_traces.get_base_column::<WORD_SIZE>(Column::RamBaseAddr);
        // Subtract previous tuple
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            // The least significant byte of the address is base_address[0] + address_offset
            tuple.push(
                base_address[0].data[vec_row]
                    + PackedBaseField::broadcast(BaseField::from(address_offset as u32)),
            );
            for base_address_limb in base_address.iter().take(WORD_SIZE).skip(1) {
                tuple.push(base_address_limb.data[vec_row]);
            }
            tuple.push(val_prev.data[vec_row]);
            for ts_prev_byte in ts_prev.into_iter() {
                tuple.push(ts_prev_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let accessed = accessed.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                (-accessed).into(),
                lookup_elements.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_subtract_address<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_prev: Column,
        ts_prev: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        let [val_prev] = trace_eval.column_eval(val_prev);
        let ts_prev = trace_eval.column_eval::<WORD_SIZE>(ts_prev);
        let [accessed] = trace_eval.column_eval(accessed);
        let base_address = trace_eval!(trace_eval, Column::RamBaseAddr);
        let mut tuple = vec![];
        // The least significant byte of the address is base_address[0] + address_offset
        tuple.push(base_address[0].clone() + E::F::from(BaseField::from(address_offset as u32)));
        for base_address_limb in base_address.iter().take(WORD_SIZE).skip(1) {
            tuple.push(base_address_limb.clone());
        }
        tuple.push(val_prev);
        for ts_prev_byte in ts_prev.into_iter() {
            tuple.push(ts_prev_byte);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-accessed).into(),
            &tuple,
        ));
    }

    fn add_access(
        original_traces: &FinalizedTraces,
        preprocessed_traces: &PreprocessedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
        val_cur: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        let [val_cur] = original_traces.get_base_column(val_cur);
        let [accessed] = original_traces.get_base_column(accessed);
        let base_address = original_traces.get_base_column::<WORD_SIZE>(Column::RamBaseAddr);
        // Add current tuple
        let clk =
            preprocessed_traces.get_preprocessed_base_column::<WORD_SIZE>(PreprocessedColumn::Clk);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            // The least significant byte of the address is base_address[0] + address_offset
            tuple.push(
                base_address[0].data[vec_row]
                    + PackedBaseField::broadcast(BaseField::from(address_offset as u32)),
            );
            for base_address_limb in base_address.iter().take(WORD_SIZE).skip(1) {
                tuple.push(base_address_limb.data[vec_row]);
            }
            tuple.push(val_cur.data[vec_row]);
            for clk_byte in clk.into_iter() {
                tuple.push(clk_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let accessed = accessed.data[vec_row];
            logup_col_gen.write_frac(
                vec_row,
                accessed.into(),
                lookup_elements.combine(tuple.as_slice()),
            );
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_add_access<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
        val_cur: Column,
        accessed: Column,
        address_offset: u8,
    ) {
        let [val_cur] = trace_eval.column_eval(val_cur);
        let [accessed] = trace_eval.column_eval(accessed);
        let base_address = trace_eval!(trace_eval, Column::RamBaseAddr);
        let clk = preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Clk);
        let mut tuple = vec![];
        // The least significant byte of the address is base_address[0] + address_offset
        tuple.push(base_address[0].clone() + E::F::from(BaseField::from(address_offset as u32)));
        for base_address_limb in base_address.iter().take(WORD_SIZE).skip(1) {
            tuple.push(base_address_limb.clone());
        }
        tuple.push(val_cur);
        for clk_byte in clk.into_iter() {
            tuple.push(clk_byte);
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);

        eval.add_to_relation(RelationEntry::new(lookup_elements, accessed.into(), &tuple));
    }

    /// Fills the interaction trace for subtracting the final content of the RW memory.
    ///
    /// - `RamInitFinalFlag` indicates whether a row should contain an final byte of the RW memory.
    /// - `RamInitFinalAddr` contains the address of the RW memory
    /// - `RamFinalValue` contains the final value of the RW memory, used if `RamInitFinalFlag` is true.
    /// - `RamFinalCounter` contains the final counter value of the RW memory at `RamInitFinalAddr`.
    ///
    /// The public output related columns do not appear here because they are constrained to use `RamFinalValue`.
    fn subtract_final_values(
        original_traces: &FinalizedTraces,
        lookup_elements: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
    ) {
        let [ram_init_final_flag] = original_traces.get_base_column(Column::RamInitFinalFlag);
        let ram_init_final_addr =
            original_traces.get_base_column::<WORD_SIZE>(Column::RamInitFinalAddr);
        let [ram_final_value] = original_traces.get_base_column(Column::RamFinalValue);
        let ram_final_counter =
            original_traces.get_base_column::<WORD_SIZE>(Column::RamFinalCounter);
        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (original_traces.log_size() - LOG_N_LANES)) {
            let mut tuple = vec![];
            for address_byte in ram_init_final_addr.iter() {
                tuple.push(address_byte.data[vec_row]);
            }
            tuple.push(ram_final_value.data[vec_row]);
            for counter_byte in ram_final_counter.iter() {
                tuple.push(counter_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let denom = lookup_elements.combine(&tuple);
            let numerator = ram_init_final_flag.data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
    }

    fn constrain_final_values<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &crate::trace::eval::TraceEval<E>,
        lookup_elements: &LoadStoreLookupElements,
    ) {
        let [ram_init_final_flag] = trace_eval!(trace_eval, Column::RamInitFinalFlag);
        let ram_init_final_addr = trace_eval!(trace_eval, Column::RamInitFinalAddr);
        let [ram_final_value] = trace_eval!(trace_eval, Column::RamFinalValue);
        let ram_final_counter = trace_eval!(trace_eval, Column::RamFinalCounter);
        let mut tuple = vec![];
        for address_byte in ram_init_final_addr.iter() {
            tuple.push(address_byte.clone());
        }
        tuple.push(ram_final_value);
        for counter_byte in ram_final_counter.iter() {
            tuple.push(counter_byte.clone());
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
        let numerator = ram_init_final_flag;

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-numerator).into(),
            &tuple,
        ));
    }
}

#[cfg(test)]
mod test {
    use crate::{
        chips::{AddChip, BeqChip, CpuChip, DecodingCheckChip, RegisterMemCheckChip, SllChip},
        machine::Machine,
        test_utils::assert_chip,
        trace::{
            program::iter_program_steps, program_trace::ProgramTracesBuilder, PreprocessedTraces,
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
            RegisterMemCheckChip,
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
            Chips::fill_main_trace(&mut traces, row_idx, &program_step, &mut side_note);
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
        Machine::<Chips>::prove(&vm_traces, &view).unwrap();
    }
}
