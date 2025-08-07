use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use nexus_vm::riscv::BuiltinOpcode;
use nexus_vm_prover_trace::{component::ComponentTrace, eval::TraceEval, trace_eval};

use super::{Column, PreprocessedColumn, StoreOp};
use crate::lookups::{LogupTraceBuilder, RangeCheckLookupElements, RangeLookupBound};

pub struct Sh;

impl StoreOp for Sh {
    const RAM2_ACCESSED: bool = true;
    const RAM3_4ACCESSED: bool = false;
    const OPCODE: BuiltinOpcode = BuiltinOpcode::SH;
    const ALIGNMENT: u8 = 2;

    fn constrain_alignment<E: EvalAtRow>(
        eval: &mut E,
        trace_eval: &TraceEval<PreprocessedColumn, Column, E>,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = trace_eval!(trace_eval, Column::IsLocalPad);
        let h_ram_base_addr = trace_eval!(trace_eval, Column::HRamBaseAddr);

        let h_ram_base_addr_aux = eval.next_trace_mask();
        // (1 − is-local-pad) · (ALIGNMENT · h-ram-base-addr-aux − h-ram-base-addr(1)) = 0
        eval.add_constraint(
            (E::F::one() - is_local_pad.clone())
                * (h_ram_base_addr_aux.clone() * BaseField::from(Self::ALIGNMENT as u32)
                    - h_ram_base_addr[0].clone()),
        );

        range_check
            .range128
            .constrain(eval, is_local_pad, h_ram_base_addr_aux);
    }

    fn generate_interaction_trace(
        logup_trace_builder: &mut LogupTraceBuilder,
        component_trace: &ComponentTrace,
        range_check: &RangeCheckLookupElements,
    ) {
        let [is_local_pad] = component_trace.original_base_column(Column::IsLocalPad);
        let h_ram_base_addr_aux = component_trace
            .original_trace
            .last()
            .expect("trace is non-empty");

        range_check.range128.generate_logup_col(
            logup_trace_builder,
            is_local_pad,
            h_ram_base_addr_aux.into(),
        );
    }
}
