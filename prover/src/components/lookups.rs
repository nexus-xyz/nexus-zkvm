//! Utilities for stwo lookups.
//!
//! Adding a chip with a lookup requires doing the following:
//!     1. Declare a relation with a [`stwo_prover::relation`] macro.
//!     2. Add this type to [`register_relation`] enum.
//!     3. Implement [`MachineChip::draw_lookup_elements`] and [`MachineChip::fill_interaction_trace`] for the chip.
//!
//! Internally, [`AllLookupElements`] is a hashmap storing a set of generated alphas and z (=lookup elements) for each
//! type. Since [`stwo_prover::constraint_framework::Relation`] is not object safe and cannot be boxed, the only way
//! to store it is by using an enum.

use std::{any::TypeId, collections::HashMap};

pub use crate::chips::{
    custom::keccak_lookups::{
        BitNotAndLookupElements as KeccakBitNotAndLookupElements,
        BitRotateLookupElements as KeccakBitRotateLookupElements,
        StateLookupElements as KeccakStateLookupElements,
        XorLookupElements as KeccakXorLookupElements,
    },
    instructions::{bit_op::BitOpLookupElements, load_store::LoadStoreLookupElements},
    memory_check::{
        program_mem_check::ProgramCheckLookupElements,
        register_mem_check::RegisterCheckLookupElements,
    },
    range_check::{
        range128::Range128LookupElements, range16::Range16LookupElements,
        range256::Range256LookupElements, range32::Range32LookupElements,
        range8::Range8LookupElements,
    },
};

// Note that this macro doesn't support a type with a qualified path, such as `bit_op::LookupElements`,
// generating unique identifiers is not easy in a declarative macro, the only sensible option is the
// `paste` crate which is now unmaintained. Therefore, make sure to either create a unique name or alias it
// in this module.
register_relation! {
    enum RelationVariant {
        BitOpLookupElements,
        LoadStoreLookupElements,
        ProgramCheckLookupElements,
        RegisterCheckLookupElements,
        Range8LookupElements,
        Range16LookupElements,
        Range32LookupElements,
        Range128LookupElements,
        Range256LookupElements,
        KeccakXorLookupElements,
        KeccakBitNotAndLookupElements,
        KeccakStateLookupElements,
        KeccakBitRotateLookupElements,
    };
    pub(crate) trait RegisteredLookupBound {}
}

#[derive(Default, Debug, Clone)]
pub struct AllLookupElements(HashMap<TypeId, RelationVariant>);

impl AllLookupElements {
    pub fn insert<T: Into<RelationVariant> + 'static>(&mut self, relation: T) {
        if self.0.insert(TypeId::of::<T>(), relation.into()).is_some() {
            panic!("attempt to insert duplicate relation")
        }
    }

    pub fn dummy() -> Self {
        Self(HashMap::from_iter(RelationVariant::dummy_array()))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: RegisteredLookupBound> AsRef<T> for AllLookupElements {
    fn as_ref(&self) -> &T {
        let variant = self
            .0
            .get(&TypeId::of::<T>())
            .expect("lookup elements weren't initialized");
        T::unwrap_ref(variant)
    }
}

macro_rules! register_relation {
    (enum $_enum:ident { $( $name:ident ),* $(,)? }; $_vis:vis trait $_trait:ident {}) => {
        #[allow(clippy::enum_variant_names)]
        #[derive(Debug, Clone)]
        pub enum $_enum {
            $($name($name),)*
        }

        $_vis trait $_trait: Sync + Clone + 'static {
            type Relation<
                F: Clone,
                EF: stwo_prover::constraint_framework::RelationEFTraitBound<F>
            >: stwo_prover::constraint_framework::Relation<F, EF>;

            fn as_relation_ref<
                F: Clone,
                EF: stwo_prover::constraint_framework::RelationEFTraitBound<F>,
            >(
                &self,
            ) -> &Self::Relation<F, EF>;

            fn unwrap_ref(it: &$_enum) -> &Self;

            fn dummy() -> Self;
        }

        $(
            impl From<$name> for $_enum {
                fn from(it: $name) -> Self {
                    Self::$name(it)
                }
            }

            impl $_trait for $name {
                type Relation<
                    F: Clone,
                    EF: stwo_prover::constraint_framework::RelationEFTraitBound<F>
                > = Self;

                fn as_relation_ref<
                    F: Clone,
                    EF: stwo_prover::constraint_framework::RelationEFTraitBound<F>,
                >(
                    &self,
                ) -> &Self::Relation<F, EF> {
                    self
                }

                fn unwrap_ref(it: &$_enum) -> &Self {
                    match it {
                        $_enum::$name(inner) => inner,
                        _ => panic!("called `unwrap` on {it:?}"),
                    }
                }

                fn dummy() -> Self {
                    Self::dummy()
                }
            }
        )*

        impl $_enum {
            #![allow(unused)]

            const NUM_VARIANTS: usize = {
                <[()]>::len(&[$($crate::components::lookups::replace_expr!($name ())),*])
            };

            fn dummy_array() -> [(std::any::TypeId, Self); Self::NUM_VARIANTS] {
                [
                    $(
                        (std::any::TypeId::of::<$name>(), Self::$name($name::dummy())),
                    )*
                ]
            }
        }
    };
}
pub(self) use register_relation;

macro_rules! replace_expr {
    ($_t:ident $sub:expr) => {
        $sub
    };
}
pub(self) use replace_expr;
