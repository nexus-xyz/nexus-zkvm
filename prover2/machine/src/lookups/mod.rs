use std::{any::TypeId, collections::HashMap};

use impl_trait_for_tuples::impl_for_tuples;

mod logup_trace_builder;
mod macros;
mod relations;

pub use self::{
    logup_trace_builder::LogupTraceBuilder,
    relations::{
        BitwiseInstrLookupElements, InstToProgMemoryLookupElements, InstToRamLookupElements,
        InstToRegisterMemoryLookupElements, ProgramExecutionLookupElements,
        ProgramMemoryReadLookupElements, RamReadWriteLookupElements, RegisterMemoryLookupElements,
    },
};

macros::register_relation! {
    enum RelationVariant {
        ProgramExecutionLookupElements,
        RegisterMemoryLookupElements,
        InstToRegisterMemoryLookupElements,
        InstToRamLookupElements,
        RamReadWriteLookupElements,
        ProgramMemoryReadLookupElements,
        InstToProgMemoryLookupElements,
        BitwiseInstrLookupElements,
    };
    pub(crate) trait RegisteredLookupBound {}
}

#[derive(Default, Debug, Clone)]
pub struct AllLookupElements(HashMap<TypeId, RelationVariant>);

impl<T: RegisteredLookupBound> AsRef<T> for AllLookupElements {
    fn as_ref(&self) -> &T {
        let variant = self
            .0
            .get(&TypeId::of::<T>())
            .expect("lookup elements weren't initialized");
        T::unwrap_ref(variant)
    }
}

mod private {
    pub trait Sealed {}
}
impl<T: RegisteredLookupBound> private::Sealed for T {}

pub(crate) trait ComponentLookupElements: private::Sealed {
    fn dummy() -> Self;

    fn get(lookup_elements: &AllLookupElements) -> Self;

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    );
}

impl<T: RegisteredLookupBound> ComponentLookupElements for T {
    fn dummy() -> Self {
        <Self as RegisteredLookupBound>::dummy()
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        let this: &Self = lookup_elements.as_ref();
        this.clone()
    }

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        let type_id = TypeId::of::<Self>();
        lookup_elements
            .0
            .entry(type_id)
            .or_insert_with(|| <Self as RegisteredLookupBound>::draw(channel).into());
    }
}

#[impl_for_tuples(5)]
#[tuple_types_custom_trait_bound(RegisteredLookupBound)]
impl private::Sealed for T {}

#[impl_for_tuples(5)]
#[tuple_types_custom_trait_bound(RegisteredLookupBound)]
#[allow(clippy::unused_unit)]
impl ComponentLookupElements for T {
    fn dummy() -> Self {
        for_tuples!( ( #( <T as ComponentLookupElements>::dummy() ),* ) )
    }

    fn get(lookup_elements: &AllLookupElements) -> Self {
        for_tuples!( ( #( <T as ComponentLookupElements>::get(lookup_elements) ),* ) )
    }

    fn draw(
        lookup_elements: &mut AllLookupElements,
        channel: &mut impl stwo_prover::core::channel::Channel,
    ) {
        for_tuples!( #( <T as ComponentLookupElements>::draw(lookup_elements, channel); )* );
    }
}
