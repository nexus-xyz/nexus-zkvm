macro_rules! replace_expr {
    ($_t:ident $sub:expr) => {
        $sub
    };
}
pub(super) use replace_expr;

macro_rules! register_relation {
    (enum $_enum:ident { $( $name:ident ),* $(,)? }; $_vis:vis trait $_trait:ident {}) => {
        #[allow(clippy::enum_variant_names)]
        #[derive(Debug, Clone)]
        pub enum $_enum {
            $($name(Box<$name>),)*
        }

        #[allow(unused)]
        $_vis trait $_trait: Sync + Clone + 'static + Into<$_enum> {
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

            fn draw(channel: &mut impl stwo_prover::core::channel::Channel) -> Self;
        }

        $(
            impl From<$name> for $_enum {
                fn from(it: $name) -> Self {
                    Self::$name(Box::new(it))
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

                #[allow(unreachable_patterns)]
                fn unwrap_ref(it: &$_enum) -> &Self {
                    match it {
                        $_enum::$name(inner) => inner,
                        _ => panic!("called `unwrap` on {it:?}"),
                    }
                }

                fn dummy() -> Self {
                    Self::dummy()
                }

                fn draw(channel: &mut impl stwo_prover::core::channel::Channel) -> Self {
                    Self::draw(channel)
                }
            }
        )*

        impl $_enum {
            #![allow(unused)]

            const NUM_VARIANTS: usize = {
                <[()]>::len(&[$($crate::lookups::macros::replace_expr!($name ())),*])
            };

            fn dummy_array() -> [(std::any::TypeId, Self); Self::NUM_VARIANTS] {
                [
                    $(
                        (std::any::TypeId::of::<$name>(), Self::$name(Box::new($name::dummy()))),
                    )*
                ]
            }
        }
    };
}
pub(super) use register_relation;
