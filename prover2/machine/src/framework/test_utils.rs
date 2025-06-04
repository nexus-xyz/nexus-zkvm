use num_traits::Zero;
use stwo_prover::{
    constraint_framework::{assert_constraints_on_polys, FrameworkEval},
    core::{
        channel::Blake2sChannel, fields::qm31::SecureField, pcs::TreeVec,
        poly::circle::CanonicCoset,
    },
};

use nexus_vm::trace::Trace;
use nexus_vm_prover_trace::eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use super::{eval::BuiltInComponentEval, BuiltInComponent, MachineComponent};
use crate::{
    lookups::{AllLookupElements, ComponentLookupElements},
    side_note::SideNote,
    BASE_COMPONENTS,
};

pub struct AssertContext<'a> {
    pub lookup_elements: AllLookupElements,
    pub side_note: SideNote<'a>,
}

impl<'a> AssertContext<'a> {
    pub fn new(trace: &'a impl Trace) -> Self {
        let mut lookup_elements = AllLookupElements::default();

        let side_note = SideNote::new(trace);

        // draw non-zero lookup elements in advance for testing
        let channel = &mut Blake2sChannel::default();
        for component in BASE_COMPONENTS {
            component.draw_lookup_elements(&mut lookup_elements, channel);
        }

        Self {
            lookup_elements,
            side_note,
        }
    }
}

/// Asserts constraints of a builtin component.
pub fn assert_component<C>(component: C, assert_ctx: &mut AssertContext) -> SecureField
where
    C: BuiltInComponent + 'static + Sync,
    C::LookupElements: 'static + Sync,
{
    let AssertContext {
        lookup_elements,
        side_note: prover_side_note,
    } = assert_ctx;

    // Main trace.
    let component_trace = component.generate_component_trace(prover_side_note);
    let log_size = component_trace.log_size();

    // Interaction trace.
    let (interaction_trace, claimed_sum) = component.generate_interaction_trace(
        component_trace.clone(),
        prover_side_note,
        lookup_elements,
    );

    let trace_evals = TreeVec::new(vec![
        component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX),
        component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX),
        interaction_trace,
    ]);
    let trace_polys = trace_evals.map(|trace| {
        trace
            .into_iter()
            .map(|c| c.interpolate())
            .collect::<Vec<_>>()
    });

    assert_constraints_on_polys(
        &trace_polys,
        CanonicCoset::new(log_size),
        |eval| {
            BuiltInComponentEval::<C> {
                component: &component,
                log_size,
                lookup_elements: C::LookupElements::get(lookup_elements),
            }
            .evaluate(eval);
        },
        claimed_sum,
    );

    claimed_sum
}

/// Computes total logup sum for a slice of components, without asserting that constraints are satisfied.
///
/// Note that depending on the logic, the ordering is important, e.g. for range checks.
pub fn components_claimed_sum(
    components: &[&dyn MachineComponent],
    ctx: &mut AssertContext,
) -> SecureField {
    let mut total_sum = SecureField::zero();

    for component in components {
        let component_trace = component.generate_component_trace(&mut ctx.side_note);

        let (_, claimed_sum) = component.generate_interaction_trace(
            component_trace.clone(),
            &ctx.side_note,
            &ctx.lookup_elements,
        );
        total_sum += claimed_sum;
    }
    total_sum
}
