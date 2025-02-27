//! Extension components of zkVM prover.
//!
//! Such components do not have access to columns defined in the base component ([`Column`](crate::column::Column)),
//! although they still can access bit-reversed main preprocessed trace if needed, or define their own. In return,
//! each component can have a smaller log size or higher constraint degree bound. Each component is expected to emit
//! a logup sum that matches with the one from the main trace, enforcing the total sum to equal to zero.
//!
//! There's no support for external our-of-crate extensions, mainly precompiles, yet. All components are considered
//! to be built-in.
//!
//! To define a new built-in component, a struct implementing [`BuiltInExtension`] must be added to [`ExtensionComponent`]
//! enum.
//!
//! Some components must always be present, for example [`final_reg::FinalReg`]. They should only be accessible within
//! the crate to avoid misuse.

use stwo_prover::{
    constraint_framework::{
        FrameworkComponent, FrameworkEval, InfoEvaluator, TraceLocationAllocator,
    },
    core::{
        air::{Component, ComponentProver},
        backend::simd::SimdBackend,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::TreeVec,
        poly::{circle::CircleEvaluation, BitReversedOrder},
        ColumnVec,
    },
};

use crate::{components::AllLookupElements, trace::sidenote::SideNote};

mod bit_op;
mod final_reg;

use bit_op::BitOpMultiplicity;
use final_reg::FinalReg;
mod multiplicity;
use multiplicity::{Multiplicity128, Multiplicity16, Multiplicity256, Multiplicity32};

trait FrameworkEvalExt: FrameworkEval + Default + Sync + 'static {
    // TODO: make it variable, e.g. derived by the component implementation from
    // the finalized side note.
    const LOG_SIZE: u32;

    fn new(lookup_elements: &AllLookupElements) -> Self;
}

trait BuiltInExtension {
    type Eval: FrameworkEvalExt;

    fn generate_preprocessed_trace(
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

    fn generate_original_trace(
        side_note: &SideNote,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

    fn generate_interaction_trace(
        side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    );

    fn to_component_prover(
        &self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend>> {
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            Self::Eval::new(lookup_elements),
            claimed_sum,
        ))
    }

    fn to_component(
        &self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        claimed_sum: SecureField,
    ) -> Box<dyn Component> {
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            Self::Eval::new(lookup_elements),
            claimed_sum,
        ))
    }

    fn trace_sizes(&self) -> TreeVec<Vec<u32>> {
        <Self as BuiltInExtension>::Eval::default()
            .evaluate(InfoEvaluator::empty())
            .mask_offsets
            .as_cols_ref()
            .map_cols(|_| Self::Eval::LOG_SIZE)
    }

    /// Returns the log_sizes of each preprocessed columns
    fn preprocessed_trace_sizes() -> Vec<u32>;
}

extension_dispatch! {
    pub enum ExtensionComponent {
        FinalReg,
        Multiplicity16,
        Multiplicity32,
        Multiplicity128,
        Multiplicity256,
        BitOpMultiplicity,
    }
}

impl ExtensionComponent {
    pub(super) const fn final_reg() -> Self {
        Self::FinalReg(FinalReg::new())
    }

    pub(super) const fn multiplicity16() -> Self {
        Self::Multiplicity16(Multiplicity16::new())
    }
    pub(super) const fn multiplicity32() -> Self {
        Self::Multiplicity32(Multiplicity32::new())
    }
    pub(super) const fn multiplicity128() -> Self {
        Self::Multiplicity128(Multiplicity128::new())
    }
    pub(super) const fn multiplicity256() -> Self {
        Self::Multiplicity256(Multiplicity256::new())
    }
    pub(super) const fn bit_op_multiplicity() -> Self {
        Self::BitOpMultiplicity(BitOpMultiplicity::new())
    }
}

// A macro mimicking enum_dispatch, but with less flexibility and therefore without shared state managing.
//
// To avoid repetitive implementations of components, the main trait [`BuiltInExtension`] features associated
// type with bound which makes it non object safe, or non dyn-compatible. External precompiles, once introduced,
// will require type-erased version of this trait since the prover crate cannot know details of implementation.
// Such precompiles can be implemented as a separate `Custom(Box<dyn ...>)` variant.
macro_rules! extension_dispatch {
    ($vis:vis enum $_enum:ident { $( $name:ident ),* $(,)? }) => {
        #[derive(Debug, Clone)]
        $vis enum $_enum {
            $($name($name),)*
        }

        $(
            impl From<$name> for $_enum {
                fn from(it: $name) -> Self {
                    Self::$name(it)
                }
            }
        )*

        impl $_enum {
            #![allow(unused)]

            pub(crate) fn generate_preprocessed_trace(
                &self,
            ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_preprocessed_trace(), )*
                }
            }

            pub(crate) fn generate_original_trace(
                &self,
                side_note: &SideNote,
            ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_original_trace(side_note), )*
                }
            }

            pub(crate) fn generate_interaction_trace(
                &self,
                side_note: &SideNote,
                lookup_elements: &AllLookupElements,
            ) -> (
                ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
                SecureField,
            ) {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_interaction_trace(side_note, lookup_elements), )*
                }
            }

            pub(crate) fn to_component_prover(
                &self,
                tree_span_provider: &mut TraceLocationAllocator,
                lookup_elements: &AllLookupElements,
                claimed_sum: SecureField,
            ) -> Box<dyn ComponentProver<SimdBackend>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::to_component_prover(inner, tree_span_provider, lookup_elements, claimed_sum), )*
                }
            }

            pub(crate) fn to_component(
                &self,
                tree_span_provider: &mut TraceLocationAllocator,
                lookup_elements: &AllLookupElements,
                claimed_sum: SecureField,
            ) -> Box<dyn Component> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::to_component(inner, tree_span_provider, lookup_elements, claimed_sum), )*
                }
            }

            pub(crate) fn trace_sizes(&self) -> TreeVec<Vec<u32>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::trace_sizes(inner), )*
                }
            }

            pub(crate) fn preprocessed_trace_sizes(&self) -> Vec<u32> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::preprocessed_trace_sizes(), )*
                }
            }
        }
    };
}
pub(self) use extension_dispatch;
