use stwo_prover::{
    constraint_framework::{assert_constraints_on_polys, FrameworkEval},
    core::{channel::Blake2sChannel, pcs::TreeVec, poly::circle::CanonicCoset},
};

use nexus_vm::trace::Trace;
use nexus_vm_prover_trace::eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use super::{eval::BuiltInComponentEval, BuiltInComponent, MachineComponent};
use crate::{
    lookups::{AllLookupElements, ComponentLookupElements},
    side_note::SideNote,
};

pub fn assert_component<C>(component: C, trace: &impl Trace)
where
    C: BuiltInComponent + 'static + Sync,
    C::LookupElements: 'static + Sync,
{
    let mut prover_side_note = SideNote::new(trace);

    let component_trace = component.generate_component_trace(&mut prover_side_note);
    let log_size = component_trace.log_size();

    // Setup protocol.
    let prover_channel = &mut Blake2sChannel::default();

    let mut lookup_elements = AllLookupElements::default();
    component.draw_lookup_elements(&mut lookup_elements, prover_channel);
    // Interaction trace.
    let (interaction_trace, claimed_sum) = component.generate_interaction_trace(
        component_trace.clone(),
        &prover_side_note,
        &lookup_elements,
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
                lookup_elements: C::LookupElements::get(&lookup_elements),
            }
            .evaluate(eval);
        },
        claimed_sum,
    );
}
