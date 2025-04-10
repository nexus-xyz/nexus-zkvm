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

use ram_init_final::RamInitFinal;
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

use crate::{
    components::AllLookupElements,
    trace::{program_trace::ProgramTraceRef, sidenote::SideNote},
};

pub(crate) mod bit_op;
pub(crate) mod final_reg;

mod multiplicity;
mod multiplicity8;
mod ram_init_final;
mod trace;

pub(crate) use trace::ComponentTrace;

use bit_op::BitOpMultiplicity;
use final_reg::FinalReg;
use multiplicity::{Multiplicity128, Multiplicity16, Multiplicity256, Multiplicity32};
use multiplicity8::Multiplicity8;

trait FrameworkEvalExt: FrameworkEval + Sync + 'static {
    fn new(log_size: u32, lookup_elements: &AllLookupElements) -> Self;
    fn dummy(log_size: u32) -> Self;
}

trait BuiltInExtension {
    type Eval: FrameworkEvalExt;

    fn generate_preprocessed_trace(
        log_size: u32,
        program_trace_ref: ProgramTraceRef,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

    fn generate_component_trace(
        log_size: u32,
        program_trace_ref: ProgramTraceRef,
        side_note: &mut SideNote,
    ) -> ComponentTrace;

    fn generate_interaction_trace(
        component_trace: ComponentTrace,
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
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn ComponentProver<SimdBackend>> {
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            Self::Eval::new(log_size, lookup_elements),
            claimed_sum,
        ))
    }

    fn to_component(
        &self,
        tree_span_provider: &mut TraceLocationAllocator,
        lookup_elements: &AllLookupElements,
        log_size: u32,
        claimed_sum: SecureField,
    ) -> Box<dyn Component> {
        Box::new(FrameworkComponent::new(
            tree_span_provider,
            Self::Eval::new(log_size, lookup_elements),
            claimed_sum,
        ))
    }

    fn compute_log_size(side_note: &SideNote) -> u32;

    fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
        <Self as BuiltInExtension>::Eval::dummy(log_size)
            .evaluate(InfoEvaluator::empty())
            .mask_offsets
            .as_cols_ref()
            .map_cols(|_| log_size)
    }

    /// Returns the log_sizes of each preprocessed columns
    fn preprocessed_trace_sizes(log_size: u32) -> Vec<u32>;
}

extension_dispatch! {
    pub enum ExtensionComponent {
        FinalReg,
        Multiplicity8,
        Multiplicity16,
        Multiplicity32,
        Multiplicity128,
        Multiplicity256,
        BitOpMultiplicity,
        RamInitFinal,
    }
}

impl ExtensionComponent {
    pub(super) const fn final_reg() -> Self {
        Self::FinalReg(FinalReg::new())
    }
    pub(super) const fn multiplicity8() -> Self {
        Self::Multiplicity8(Multiplicity8::new())
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
    pub(super) const fn ram_init_final() -> Self {
        Self::RamInitFinal(RamInitFinal::new())
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
                log_size: u32,
                program_trace_ref: ProgramTraceRef,
            ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_preprocessed_trace(log_size, program_trace_ref), )*
                }
            }

            pub(crate) fn generate_component_trace(
                &self,
                log_size: u32,
                program_trace_ref: ProgramTraceRef,
                side_note: &mut SideNote,
            ) -> ComponentTrace {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_component_trace(log_size, program_trace_ref, side_note), )*
                }
            }

            pub(crate) fn generate_interaction_trace(
                &self,
                component_trace: ComponentTrace,
                side_note: &SideNote,
                lookup_elements: &AllLookupElements,
            ) -> (
                ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
                SecureField,
            ) {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::generate_interaction_trace(component_trace, side_note, lookup_elements), )*
                }
            }

            pub(crate) fn to_component_prover(
                &self,
                tree_span_provider: &mut TraceLocationAllocator,
                lookup_elements: &AllLookupElements,
                log_size: u32,
                claimed_sum: SecureField,
            ) -> Box<dyn ComponentProver<SimdBackend>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::to_component_prover(inner, tree_span_provider, lookup_elements, log_size, claimed_sum), )*
                }
            }

            pub(crate) fn to_component(
                &self,
                tree_span_provider: &mut TraceLocationAllocator,
                lookup_elements: &AllLookupElements,
                log_size: u32,
                claimed_sum: SecureField,
            ) -> Box<dyn Component> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::to_component(inner, tree_span_provider, lookup_elements, log_size, claimed_sum), )*
                }
            }

            pub(crate) fn compute_log_size(&self, side_note: &SideNote) -> u32 {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::compute_log_size(side_note), )*
                }
            }

            pub(crate) fn trace_sizes(&self, log_size: u32) -> TreeVec<Vec<u32>> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::trace_sizes(inner, log_size), )*
                }
            }

            pub(crate) fn preprocessed_trace_sizes(&self, log_size: u32) -> Vec<u32> {
                match self {
                    $( $_enum::$name(inner) => <$name as BuiltInExtension>::preprocessed_trace_sizes(log_size), )*
                }
            }
        }
    };
}
pub(self) use extension_dispatch;
