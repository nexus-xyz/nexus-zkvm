//! Custom instructions handler chip.
//!
//! Extensions handle memory checking, but the corresponding flags and decoding still must be constrained within
//! the main component.

use nexus_common::constants::KECCAKF_OPCODE;
use nexus_vm::{
    memory::{MemAccessSize, MemoryRecord},
    WORD_SIZE,
};
use num_traits::One;
use stwo::core::channel::Channel;

use crate::{
    column::Column,
    components::AllLookupElements,
    extensions::ExtensionsConfig,
    trace::{
        eval::{trace_eval, TraceEval},
        sidenote::SideNote,
        ProgramStep, TracesBuilder,
    },
    traits::MachineChip,
};

/// The custom instruction chip works as an (optional) bridge between main component and custom extensions.
/// It **doesn't** constrain the result of execution of custom instructions.
pub type CustomInstructionChip = (KeccakChip,);

pub struct KeccakChip;

pub mod keccak_lookups {
    const BITWISE_TABLE_LOOKUP_SIZE: usize = 3;
    stwo_constraint_framework::relation!(XorLookupElements, BITWISE_TABLE_LOOKUP_SIZE);
    stwo_constraint_framework::relation!(BitNotAndLookupElements, BITWISE_TABLE_LOOKUP_SIZE);

    const BIT_ROTATE_TABLE_LOOKUP_SIZE: usize = 4;
    stwo_constraint_framework::relation!(BitRotateLookupElements, BIT_ROTATE_TABLE_LOOKUP_SIZE);

    pub use state::StateLookupElements;
    mod state {
        // state lookup requires combining a large tuple and can blow up the size of the enum,
        // therefore wrap it into box (alternative is to modify enum macro to support boxed relations)

        const STATE_LOOKUP_SIZE: usize = 25 * 8;
        stwo_constraint_framework::relation!(RawStateLookupElements, STATE_LOOKUP_SIZE);

        #[derive(Debug, Clone)]
        pub struct StateLookupElements(Box<RawStateLookupElements>);
        impl StateLookupElements {
            pub fn draw(channel: &mut impl stwo::core::channel::Channel) -> Self {
                Self(Box::new(RawStateLookupElements::draw(channel)))
            }
            pub fn dummy() -> Self {
                Self(Box::new(RawStateLookupElements::dummy()))
            }
        }
        impl<F: Clone, EF: stwo_constraint_framework::RelationEFTraitBound<F>>
            stwo_constraint_framework::Relation<F, EF> for StateLookupElements
        {
            fn combine(&self, values: &[F]) -> EF {
                <RawStateLookupElements as stwo_constraint_framework::Relation<F, EF>>::combine(
                    &self.0, values,
                )
            }

            fn get_name(&self) -> &str {
                <RawStateLookupElements as stwo_constraint_framework::Relation<F, EF>>::get_name(
                    &self.0,
                )
            }

            fn get_size(&self) -> usize {
                <RawStateLookupElements as stwo_constraint_framework::Relation<F, EF>>::get_size(
                    &self.0,
                )
            }
        }
    }
}

impl KeccakChip {
    fn keccak_input_from_mem_records(addr: u32, step: &ProgramStep) -> [u64; 25] {
        let mut input = [0u32; 50];
        for record in &step.step.memory_records {
            // (size, address, value)
            let MemoryRecord::LoadRecord(memory_read, _) = *record else {
                continue;
            };
            let (size, address, value) = memory_read;
            assert_eq!(size, MemAccessSize::Word);
            let idx = (address - addr) / WORD_SIZE as u32;
            input[idx as usize] = value;
        }
        let mut state = [0u64; 25];
        for (i, c) in input.chunks_exact(2).enumerate() {
            let low = c[0] as u64;
            let high = c[1] as u64;
            state[i] = low + (high << 32);
        }
        state
    }

    /// Modifies side-note timestamps for accessed memory and returns previous values.
    fn update_state_timestamps(addr: u32, input: &[u64; 25], side_note: &mut SideNote) -> Vec<u32> {
        let output = {
            let mut input = *input;
            tiny_keccak::keccakf(&mut input);
            input
        };
        let mut timestamps = Vec::with_capacity(WORD_SIZE * 25);
        for (i, byte) in output.into_iter().flat_map(u64::to_le_bytes).enumerate() {
            let addr = addr + i as u32;
            let (ts, prev_val) = side_note.rw_mem_check.last_access.entry(addr).or_default();
            timestamps.push(*ts);

            *ts += 1;
            *prev_val = byte;
        }
        timestamps
    }
}

impl MachineChip for KeccakChip {
    fn draw_lookup_elements(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl Channel,
        config: &ExtensionsConfig,
    ) {
        if !config.is_keccak_enabled() {
            return;
        }
        lookup_elements.insert(keccak_lookups::XorLookupElements::draw(channel));
        lookup_elements.insert(keccak_lookups::BitNotAndLookupElements::draw(channel));
        lookup_elements.insert(keccak_lookups::StateLookupElements::draw(channel));
        lookup_elements.insert(keccak_lookups::BitRotateLookupElements::draw(channel));
    }

    fn fill_main_trace(
        traces: &mut TracesBuilder,
        row_idx: usize,
        vm_step: &Option<ProgramStep>,
        side_note: &mut SideNote,
        config: &ExtensionsConfig,
    ) {
        let Some(step) = vm_step
            .as_ref()
            .filter(|step| !step.step.instruction.opcode.is_builtin())
        else {
            return;
        };
        if step.step.instruction.opcode.raw != KECCAKF_OPCODE {
            return;
        } else {
            assert!(
                config.is_keccak_enabled(),
                "keccakf instruction is only supported with enabled extensions",
            );
        }

        let reg = step.step.instruction.op_a;
        let addr = step.regs[reg];

        let input = Self::keccak_input_from_mem_records(addr, step);
        let timestamps = Self::update_state_timestamps(addr, &input, side_note);

        let keccak_side_note = &mut side_note.keccak;
        keccak_side_note.inputs.push(input);
        keccak_side_note.addresses.push(addr);
        keccak_side_note.timestamps.push(timestamps);

        traces.fill_columns(row_idx, reg as u8, Column::OpA);
        traces.fill_columns(row_idx, true, Column::IsCustomKeccak);
    }

    fn add_constraints<E: stwo_constraint_framework::EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<E>,
        _lookup_elements: &AllLookupElements,
        config: &ExtensionsConfig,
    ) {
        let [is_custom_keccak] = trace_eval!(trace_eval, Column::IsCustomKeccak);
        if !config.is_keccak_enabled() {
            // Enforce that the custom instruction flag is always zero when extensions are disabled.
            //
            // In practice, the column should be removed from the trace, however it requires major refactoring
            // of trace generation interfaces to enable dynamic trace indexing.
            eval.add_constraint(is_custom_keccak);
            return;
        }

        eval.add_constraint(is_custom_keccak.clone() * (E::F::one() - is_custom_keccak.clone()));
        // TODO: constrain instruction decoding and register access.
    }
}
