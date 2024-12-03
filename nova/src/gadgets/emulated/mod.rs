use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::ToBytesGadget,
    convert::ToConstraintFieldGadget,
    fields::{
        emulated_fp::{params::OptimizationType, AllocatedEmulatedFpVar, EmulatedFpVar},
        fp::FpVar,
    },
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, OptimizationGoal, SynthesisError};

pub mod short_weierstrass;

/// Mirror of [`cast_field_element_unique`](crate::utils::cast_field_element_unique) for allocated input.
pub fn cast_field_element_unique<F1, F2>(
    elem: &EmulatedFpVar<F1, F2>,
) -> Result<Vec<FpVar<F2>>, SynthesisError>
where
    F1: PrimeField,
    F2: PrimeField,
{
    elem.to_bytes_le()?.to_constraint_field()
}

/// Extension of [`AllocVar`] for allocating variables assuming they're well-formed, primarily witnesses.
// NOTE: this trait should not be used until https://github.com/nexus-xyz/supernova/issues/19 is resolved.
pub trait AllocVarExt<V, F: Field>: AllocVar<V, F>
where
    Self: Sized,
    V: ?Sized,
{
    /// Allocates a new variable of type `Self` in the `ConstraintSystem` `cs`.
    /// The mode of allocation is decided by `mode`.
    ///
    /// This should not create any constraints.
    #[allow(dead_code)]
    fn new_variable_unconstrained<T: Borrow<V>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError>;
}

impl<TargetField: PrimeField, BaseField: PrimeField> AllocVarExt<TargetField, BaseField>
    for EmulatedFpVar<TargetField, BaseField>
{
    fn new_variable_unconstrained<T: Borrow<TargetField>>(
        cs: impl Into<Namespace<BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        if cs == ConstraintSystemRef::None || mode == AllocationMode::Constant {
            Ok(Self::Constant(*f()?.borrow()))
        } else {
            let optimization_type = match cs.optimization_goal() {
                OptimizationGoal::None => OptimizationType::Constraints,
                OptimizationGoal::Constraints => OptimizationType::Constraints,
                OptimizationGoal::Weight => OptimizationType::Weight,
            };

            let zero = TargetField::zero();

            let elem = match f() {
                Ok(t) => *(t.borrow()),
                Err(_) => zero,
            };
            let elem_representations =
                AllocatedEmulatedFpVar::get_limbs_representations(&elem, optimization_type)?;
            let mut limbs = Vec::new();

            for limb in elem_representations.iter() {
                limbs.push(FpVar::<BaseField>::new_variable(
                    ark_relations::ns!(cs, "alloc"),
                    || Ok(limb),
                    mode,
                )?);
            }

            Ok(Self::Var(AllocatedEmulatedFpVar {
                cs,
                limbs,
                num_of_additions_over_normal_form: BaseField::zero(),
                is_in_the_normal_form: true,
                target_phantom: PhantomData,
            }))
        }
    }
}
