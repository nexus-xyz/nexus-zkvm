
pub fn project_augmented_circuit_size(sc: &StepCircuit<G1::ScalarField>) -> usize {

    // The direct construction from the HyperNova paper has a circular definition: the size
    // of the augmented circuit is dependent on the number of rounds of the sumcheck (`s`),
    // but the number of rounds of the sumcheck is dependent (logarithmically) on the size
    // of the augmented circuit.
    //
    // Luckily, since the dependency is logarithmic we should pretty easily find a fixpoint
    // where this circularity stabilizes. This function does that projection so that we can
    // use the correct augmented circuit size everywhere from the start. But, a tradeoff is
    // that if any alterations are made to the augmented circuit then the constants in this
    // function will need to be recomputed and updated.
    //
    // For an example of how this computation works, imagine the number of base constraints
    // (those neither in the step circuit or in sumcheck) is 20, each sumcheck round is 10,
    // and the step circuit is 2. Then we will need at least
    //
    //     2^4 < 22 < 2^5 --> 5
    //
    // sumcheck rounds. So that gives us an augmented circuit size of 72. But this means we
    // will need at least
    //
    //     2^6 < 72 < 2^7 --> 7
    //
    // sumcheck rounds. So that gives an augmented circuit with size 92, which is a fixpoint
    // as 7 sumcheck rounds remains sufficient.

    const BASE_CONSTRAINTS: usize; // number of constraints in augmented circuit, not including sumcheck
    const SUMCHECK_ROUND_CONSTRAINTS: usize; // number of constraints per sumcheck round

    // compute step circuit size

    // compute number of sumcheck rounds needed without any sumcheck
    let mut low = ;
    let mut high = ;

    // loop:

    let s: usize = ((shape.num_constraints - 1).checked_ilog2().unwrap_or(0) + 1) as usize;


}
