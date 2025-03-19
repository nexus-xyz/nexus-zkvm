use itertools::Itertools;
use nexus_vm::WORD_SIZE;
use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::{
        logup::LogupTraceGenerator, preprocessed_columns::PreProcessedColumnId, EvalAtRow,
        FrameworkEval, Relation, RelationEntry,
    },
    core::{
        backend::simd::{
            column::BaseColumn,
            m31::{PackedBaseField, LOG_N_LANES},
            SimdBackend,
        },
        fields::{m31::BaseField, qm31::SecureField},
        poly::{
            circle::{CanonicCoset, CircleEvaluation},
            BitReversedOrder,
        },
        ColumnVec,
    },
};

use crate::{
    chips::{
        instructions::load_store::LoadStoreLookupElements,
        range_check::range256::Range256LookupElements,
    },
    components::AllLookupElements,
    trace::{program_trace::ProgramTraceParams, sidenote::SideNote, utils::IntoBaseFields},
};

use super::{BuiltInExtension, FrameworkEvalExt};

/// An extension component for initial write set and final read set of the RAM memory checking
#[derive(Debug, Clone)]
pub struct RamInitFinal {
    _private: (),
}

impl RamInitFinal {
    const NUM_PREPROCESSED_TRACE_COLS: usize = WORD_SIZE + 4;
    pub(super) const fn new() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct RamInitFinalEval {
    log_size: u32,
    load_store_elements: LoadStoreLookupElements,
    range256_elements: Range256LookupElements,
}

impl FrameworkEval for RamInitFinalEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: stwo_prover::constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        // Retrieve all preprocessed columns in the same order as generated
        let preprocessed_ram_addr: Vec<E::F> = (0..WORD_SIZE)
            .map(|i| {
                let col_id = format!("preprocessed_ram_init_final_addr{}", i);
                eval.get_preprocessed_column(PreProcessedColumnId { id: col_id })
            })
            .collect();

        let preprocessed_init_flag = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "preprocessed_ram_init_final_init_flag".to_owned(),
        });
        let preprocessed_init_value = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "preprocessed_ram_init_final_init_value".to_owned(),
        });
        let preprocessed_output_flag = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "preprocessed_ram_init_final_output_flag".to_owned(),
        });
        let preprocessed_output_value = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "preprocessed_ram_init_final_output_value".to_owned(),
        });
        // The byte-address of RAM initial & final states. Each row contains information about one byte of initial & final RAM states.
        let ram_init_final_addr = (0..WORD_SIZE).map(|_| eval.next_trace_mask()).collect_vec();
        // The flag indicating whether (RamInitFinalAddr, RamFinalValue, RamFinalCounter) represents a byte in the final RAM state.
        let ram_init_final_flag = eval.next_trace_mask();
        // The final value of the RAM at address RamInitFinalAddr
        let ram_final_value = eval.next_trace_mask();
        // The final access counter value of the RAM at address RamInitFinalAddr
        let ram_final_counter = (0..WORD_SIZE).map(|_| eval.next_trace_mask()).collect_vec();

        // For each limb of the address, enforce:
        // (initial_memory_flag + public_output_flag) * (ram_init_final_addr[i] - public_ram_addr[i]) = 0
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                (preprocessed_init_flag.clone() + preprocessed_output_flag.clone())
                    * (ram_init_final_addr[i].clone() - preprocessed_ram_addr[i].clone()),
            );
        }
        // Enforce: public_output_flag * (ram_final_value - public_output_value) = 0
        eval.add_constraint(
            preprocessed_output_flag * (ram_final_value.clone() - preprocessed_output_value),
        );

        // Enforce RemInitFinalFlag is boolean
        eval.add_constraint(
            ram_init_final_flag.clone() * (ram_init_final_flag.clone() - E::F::one()),
        );

        self.constrain_add_initial_values(
            &mut eval,
            &ram_init_final_addr,
            preprocessed_init_flag,
            preprocessed_init_value,
            ram_init_final_flag.clone(),
        );
        self.constrain_subtract_final_values(
            &mut eval,
            &ram_init_final_addr,
            ram_final_value.clone(),
            &ram_final_counter,
            ram_init_final_flag,
        );
        self.constrain_add_range256_occurrences(
            &mut eval,
            &ram_init_final_addr,
            ram_final_value,
            &ram_final_counter,
        );

        eval.finalize_logup();

        eval
    }
}

impl FrameworkEvalExt for RamInitFinalEval {
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self {
        let load_store_lookup_elements: &LoadStoreLookupElements = lookup_elements.as_ref();
        let range256_lookup_elements: &Range256LookupElements = lookup_elements.as_ref();
        Self {
            log_size,
            load_store_elements: load_store_lookup_elements.clone(),
            range256_elements: range256_lookup_elements.clone(),
        }
    }
    fn dummy(log_size: u32) -> Self {
        Self {
            log_size,
            load_store_elements: LoadStoreLookupElements::dummy(),
            range256_elements: Range256LookupElements::dummy(),
        }
    }
}

impl RamInitFinalEval {
    fn constrain_add_initial_values<E: EvalAtRow>(
        &self,
        eval: &mut E,
        ram_init_final_addr: &[E::F],
        preprocessed_init_flag: E::F,
        preprocessed_init_value: E::F,
        ram_init_final_flag: E::F,
    ) {
        let mut tuple = vec![];
        // Build the tuple from the RAM address bytes.
        for address in ram_init_final_addr.iter() {
            tuple.push(address.clone());
        }
        // Add the product of preprocessed init flag and value.
        tuple.push(preprocessed_init_flag * preprocessed_init_value);
        // Append WORD_SIZE zeros as the counter.
        for _ in 0..WORD_SIZE {
            tuple.push(E::F::zero());
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
        let numerator = ram_init_final_flag;
        eval.add_to_relation(RelationEntry::new(
            &self.load_store_elements,
            numerator.into(),
            &tuple,
        ));
    }
    fn constrain_subtract_final_values<E: EvalAtRow>(
        &self,
        eval: &mut E,
        ram_init_final_addr: &[E::F],
        ram_final_value: E::F,
        ram_final_counter: &[E::F],
        ram_init_final_flag: E::F,
    ) {
        let mut tuple = vec![];
        for address in ram_init_final_addr.iter() {
            tuple.push(address.clone());
        }
        tuple.push(ram_final_value);
        for counter in ram_final_counter.iter() {
            tuple.push(counter.clone());
        }
        assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
        let numerator = ram_init_final_flag;
        eval.add_to_relation(RelationEntry::new(
            &self.load_store_elements,
            (-numerator).into(),
            &tuple,
        ));
    }
    fn constrain_add_range256_occurrences<E: EvalAtRow>(
        &self,
        eval: &mut E,
        ram_init_final_addr: &[E::F],
        ram_final_value: E::F,
        ram_final_counter: &[E::F],
    ) {
        for ram_init_final_addr_byte in ram_init_final_addr.iter() {
            let checked_tuple = vec![ram_init_final_addr_byte.clone()];
            eval.add_to_relation(RelationEntry::new(
                &self.range256_elements,
                SecureField::one().into(),
                &checked_tuple,
            ));
        }
        let checked_tuple = vec![ram_final_value];
        eval.add_to_relation(RelationEntry::new(
            &self.range256_elements,
            SecureField::one().into(),
            &checked_tuple,
        ));
        for ram_final_counter_byte in ram_final_counter.iter() {
            let checked_tuple = vec![ram_final_counter_byte.clone()];
            eval.add_to_relation(RelationEntry::new(
                &self.range256_elements,
                SecureField::one().into(),
                &checked_tuple,
            ));
        }
    }
}

impl BuiltInExtension for RamInitFinal {
    type Eval = RamInitFinalEval;

    fn generate_preprocessed_trace(
        log_size: u32,
        program_trace_params: ProgramTraceParams,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(log_size).circle_domain();
        let preprocessed_cols = Self::preprocessed_columns(log_size, program_trace_params);
        preprocessed_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn preprocessed_trace_sizes(log_size: u32) -> Vec<u32> {
        vec![log_size; Self::NUM_PREPROCESSED_TRACE_COLS]
    }

    fn generate_original_trace(
        log_size: u32,
        side_note: &mut SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let original_cols = Self::original_columns(log_size, side_note);
        // update multiplicity for init_final_addr
        for col in &original_cols[0..WORD_SIZE] {
            Self::update_range256_multiplicities(col, side_note);
        }
        // udpate multiplicity for final_value
        let final_value_col = &original_cols[WORD_SIZE + 1];
        Self::update_range256_multiplicities(final_value_col, side_note);
        // update multiplicity for final_counter
        for col in &original_cols[WORD_SIZE + 2..WORD_SIZE + 2 + WORD_SIZE] {
            Self::update_range256_multiplicities(col, side_note);
        }
        let domain = CanonicCoset::new(log_size).circle_domain();
        original_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect()
    }

    fn generate_interaction_trace(
        log_size: u32,
        program_trace_params: ProgramTraceParams,
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let load_store_elements: &LoadStoreLookupElements = lookup_elements.as_ref();
        let range256_elements: &Range256LookupElements = lookup_elements.as_ref();
        let preprocessed_cols = Self::preprocessed_columns(log_size, program_trace_params);
        let original_cols = Self::original_columns(log_size, side_note);

        let mut logup_trace_gen = LogupTraceGenerator::new(log_size);

        Self::add_initial_values(
            log_size,
            &preprocessed_cols,
            &original_cols,
            load_store_elements,
            &mut logup_trace_gen,
        );

        Self::subtract_final_values(
            log_size,
            &original_cols,
            load_store_elements,
            &mut logup_trace_gen,
        );

        Self::add_range256_occurrences(
            log_size,
            &original_cols,
            range256_elements,
            &mut logup_trace_gen,
        );

        logup_trace_gen.finalize_last()
    }
    fn compute_log_size(side_note: &SideNote) -> u32 {
        let num_entries = side_note.rw_mem_check.last_access.len();
        let log_size = num_entries.next_power_of_two().trailing_zeros();
        log_size.max(LOG_N_LANES)
    }
}

impl RamInitFinal {
    fn preprocessed_columns(
        log_size: u32,
        program_trace_params: ProgramTraceParams,
    ) -> Vec<BaseColumn> {
        let total_len = program_trace_params.init_memory.len()
            + program_trace_params.exit_code.len()
            + program_trace_params.public_output.len();
        let padding_length = (1usize << log_size)
            .checked_sub(total_len)
            .expect("log_size too small");
        let mut preprocessed_cols = vec![];

        // Iterator for PublicRamAddr: take the address from each group.
        let public_ram_addr_iter = program_trace_params
            .init_memory
            .iter()
            .map(|entry| entry.address)
            .chain(
                program_trace_params
                    .exit_code
                    .iter()
                    .map(|entry| entry.address),
            )
            .chain(
                program_trace_params
                    .public_output
                    .iter()
                    .map(|entry| entry.address),
            )
            .chain(std::iter::repeat(0).take(padding_length));
        let public_ram_addr_iter = public_ram_addr_iter
            .map(|address| -> [BaseField; WORD_SIZE] { address.into_base_fields() });
        assert_eq!(public_ram_addr_iter.clone().count(), 1 << log_size);
        (0..WORD_SIZE).for_each(|i| {
            let base_column =
                BaseColumn::from_iter(public_ram_addr_iter.clone().map(|address| address[i]));
            preprocessed_cols.push(base_column);
        });

        // Iterator for PublicInitialMemoryFlag: true for init_memory rows, false for others.
        let public_initial_memory_flag_iter = program_trace_params
            .init_memory
            .iter()
            .map(|_| true)
            .chain(std::iter::repeat(false).take(program_trace_params.exit_code.len()))
            .chain(std::iter::repeat(false).take(program_trace_params.public_output.len()))
            .chain(std::iter::repeat(false).take(padding_length));
        assert_eq!(
            public_initial_memory_flag_iter.clone().count(),
            1 << log_size
        );
        let public_initial_memory_flag_iter =
            public_initial_memory_flag_iter.map(|flag| flag.into_base_fields()[0]);
        let public_initial_memory_flag_column =
            BaseColumn::from_iter(public_initial_memory_flag_iter);
        preprocessed_cols.push(public_initial_memory_flag_column);

        // Iterator for PublicInitialMemoryValue: use the init_memory value, zero otherwise.
        let public_initial_memory_value_iter = program_trace_params
            .init_memory
            .iter()
            .map(|entry| entry.value)
            .chain(std::iter::repeat(0).take(program_trace_params.exit_code.len()))
            .chain(std::iter::repeat(0).take(program_trace_params.public_output.len()))
            .chain(std::iter::repeat(0).take(padding_length));
        assert_eq!(
            public_initial_memory_value_iter.clone().count(),
            1 << log_size
        );
        let public_initial_memory_value_iter =
            public_initial_memory_value_iter.map(|value| value.into_base_fields());
        let base_column =
            BaseColumn::from_iter(public_initial_memory_value_iter.map(|value| value[0]));
        preprocessed_cols.push(base_column);

        // Iterator for PublicOutputFlag: false for init_memory rows, true for exit_code and public_output.
        let public_output_flag_iter = std::iter::repeat(false)
            .take(program_trace_params.init_memory.len())
            .chain(program_trace_params.exit_code.iter().map(|_| true))
            .chain(program_trace_params.public_output.iter().map(|_| true))
            .chain(std::iter::repeat(false).take(padding_length));
        assert_eq!(public_output_flag_iter.clone().count(), 1 << log_size);
        let public_output_flag_iter =
            public_output_flag_iter.map(|flag| flag.into_base_fields()[0]);
        let public_output_flag_column = BaseColumn::from_iter(public_output_flag_iter);
        preprocessed_cols.push(public_output_flag_column);

        // Iterator for PublicOutputValue: zero for init_memory rows, use the provided value for the others.
        let public_output_value_iter = std::iter::repeat(0)
            .take(program_trace_params.init_memory.len())
            .chain(
                program_trace_params
                    .exit_code
                    .iter()
                    .map(|entry| entry.value),
            )
            .chain(
                program_trace_params
                    .public_output
                    .iter()
                    .map(|entry| entry.value),
            )
            .chain(std::iter::repeat(0).take(padding_length));
        assert_eq!(public_output_value_iter.clone().count(), 1 << log_size);
        let public_output_value_iter =
            public_output_value_iter.map(|value| value.into_base_fields());
        let base_column = BaseColumn::from_iter(public_output_value_iter.map(|value| value[0]));
        preprocessed_cols.push(base_column);
        assert_eq!(preprocessed_cols.len(), Self::NUM_PREPROCESSED_TRACE_COLS);
        preprocessed_cols
    }
    fn original_columns(log_size: u32, side_note: &SideNote) -> Vec<BaseColumn> {
        // First, create an iterator on rw_mem_check_last_access extended to the expected number of rows.
        let num_rows = 1usize << log_size;
        let num_entries = side_note.rw_mem_check.last_access.len();
        let num_extension = num_rows
            .checked_sub(num_entries)
            .expect("Mistake in ram_init_final_log_size computation");
        let extended_iter = side_note
            .rw_mem_check
            .last_access
            .iter()
            .map(Some)
            .chain(std::iter::repeat(None).take(num_extension));
        let mut ret = vec![];
        let ram_init_final_addrs = extended_iter
            .clone()
            .map(|entry| entry.map_or_else(|| 0u32, |(address, _last_access)| *address));
        let ram_init_final_addrs = ram_init_final_addrs
            .map(|address| -> [BaseField; WORD_SIZE] { address.into_base_fields() });
        (0..WORD_SIZE).for_each(|i| {
            let base_column =
                BaseColumn::from_iter(ram_init_final_addrs.clone().map(|address| address[i]));
            ret.push(base_column);
        });
        let ram_init_final_flag = extended_iter
            .clone()
            .map(|entry| entry.is_some().into_base_fields()[0]);
        let ram_init_final_flag = BaseColumn::from_iter(ram_init_final_flag);
        ret.push(ram_init_final_flag);
        let ram_final_values = extended_iter.clone().map(|entry| {
            entry.map_or_else(
                BaseField::zero,
                |(_address, (_last_counter, last_value))| BaseField::from(*last_value as u32),
            )
        });
        let ram_final_values = BaseColumn::from_iter(ram_final_values);
        ret.push(ram_final_values);
        let ram_final_counters = extended_iter.map(|entry| {
            entry.map_or_else(
                || [BaseField::zero(); WORD_SIZE],
                |(_address, (last_counter, _last_value))| last_counter.into_base_fields(),
            )
        });
        (0..WORD_SIZE).for_each(|i| {
            let base_column =
                BaseColumn::from_iter(ram_final_counters.clone().map(|counter| counter[i]));
            ret.push(base_column);
        });
        ret.iter().enumerate().for_each(|(i, col)| {
            assert_eq!(col.length, num_rows, "{}th element has wrong length", i);
        });
        assert!(ret.len() == 2 * WORD_SIZE + 2);
        ret
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
        log_size: u32,
        preprocessed_cols: &[BaseColumn],
        original_cols: &[BaseColumn],
        lookup_element: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
    ) {
        let _preprocessed_ram_init_final_addr = &preprocessed_cols[0..WORD_SIZE];
        let initial_memory_flag = &preprocessed_cols[WORD_SIZE];
        let initial_memory_value = &preprocessed_cols[WORD_SIZE + 1];
        let _preprocessed_output_flag = &preprocessed_cols[WORD_SIZE + 2];
        let _preprocessed_output_value = &preprocessed_cols[WORD_SIZE + 3];
        assert_eq!(preprocessed_cols.len(), Self::NUM_PREPROCESSED_TRACE_COLS);

        let ram_init_final_addr = &original_cols[0..WORD_SIZE];
        let ram_init_final_flag = &original_cols[WORD_SIZE];
        let _ram_final_value = &original_cols[WORD_SIZE + 1];
        let _ram_final_counter = &original_cols[WORD_SIZE + 2..WORD_SIZE + 2 + WORD_SIZE];
        assert_eq!(original_cols.len(), WORD_SIZE + 2 + WORD_SIZE);

        let mut logup_col_gen = logup_trace_gen.new_col();
        // Add (address, value, 0)
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let mut tuple = vec![];
            for address_byte in ram_init_final_addr.iter() {
                tuple.push(address_byte.data[vec_row]);
            }
            tuple.push(initial_memory_flag.data[vec_row] * initial_memory_value.data[vec_row]);
            // The counter is zero
            tuple.extend_from_slice(&[PackedBaseField::zero(); WORD_SIZE]);
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let denom = lookup_element.combine(&tuple);
            let numerator = ram_init_final_flag.data[vec_row];
            logup_col_gen.write_frac(vec_row, numerator.into(), denom);
        }
        logup_col_gen.finalize_col();
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
        log_size: u32,
        original_cols: &[BaseColumn],
        lookup_element: &LoadStoreLookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
    ) {
        let ram_init_final_addr = &original_cols[0..WORD_SIZE];
        let ram_init_final_flag = &original_cols[WORD_SIZE];
        let ram_final_value = &original_cols[WORD_SIZE + 1];
        let ram_final_counter = &original_cols[WORD_SIZE + 2..WORD_SIZE + 2 + WORD_SIZE];
        assert_eq!(original_cols.len(), WORD_SIZE + 2 + WORD_SIZE);

        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let mut tuple = vec![];
            for address_byte in ram_init_final_addr.iter() {
                tuple.push(address_byte.data[vec_row]);
            }
            tuple.push(ram_final_value.data[vec_row]);
            for counter_byte in ram_final_counter.iter() {
                tuple.push(counter_byte.data[vec_row]);
            }
            assert_eq!(tuple.len(), 2 * WORD_SIZE + 1);
            let denom = lookup_element.combine(&tuple);
            let numerator = ram_init_final_flag.data[vec_row];
            logup_col_gen.write_frac(vec_row, (-numerator).into(), denom);
        }
        logup_col_gen.finalize_col();
    }
    fn add_range256_occurrences(
        log_size: u32,
        original_cols: &[BaseColumn],
        lookup_element: &Range256LookupElements,
        logup_trace_gen: &mut LogupTraceGenerator,
    ) {
        let ram_init_final_addr = &original_cols[0..WORD_SIZE];
        let _ram_init_final_flag = &original_cols[WORD_SIZE];
        let ram_final_value = &original_cols[WORD_SIZE + 1];
        let ram_final_counter = &original_cols[WORD_SIZE + 2..WORD_SIZE + 2 + WORD_SIZE];
        assert_eq!(original_cols.len(), WORD_SIZE + 2 + WORD_SIZE);

        for ram_init_final_addr_byte in ram_init_final_addr.iter() {
            let mut logup_col_gen = logup_trace_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let checked_tuple = vec![ram_init_final_addr_byte.data[vec_row]];
                let denom = lookup_element.combine(&checked_tuple);
                logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
            }
            logup_col_gen.finalize_col();
        }

        let mut logup_col_gen = logup_trace_gen.new_col();
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let checked_tuple = vec![ram_final_value.data[vec_row]];
            let denom = lookup_element.combine(&checked_tuple);
            logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
        }
        logup_col_gen.finalize_col();
        for ram_final_counter_byte in ram_final_counter.iter() {
            let mut logup_col_gen = logup_trace_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let checked_tuple = vec![ram_final_counter_byte.data[vec_row]];
                let denom = lookup_element.combine(&checked_tuple);
                logup_col_gen.write_frac(vec_row, SecureField::one().into(), denom);
            }
            logup_col_gen.finalize_col();
        }
    }
    /// A utility function for updating the range256 multiplicities for a BaseColumn
    fn update_range256_multiplicities(col: &BaseColumn, side_note: &mut SideNote) {
        for (_i, elm) in col.as_slice().iter().enumerate() {
            let checked = elm.0;
            #[cfg(not(test))]
            assert!(
                checked < 256,
                "final value {} out of range at index {}",
                checked,
                _i
            );
            side_note.range256.multiplicity[checked as usize] += 1;
        }
    }
}
