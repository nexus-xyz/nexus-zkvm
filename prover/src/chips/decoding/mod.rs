// This module contains chips about instruction decoding.

mod type_b;
mod type_i;
mod type_j;
mod type_r;
mod type_sys;
mod type_u;

pub use self::{
    type_b::TypeBChip, type_i::TypeIChip, type_j::TypeJChip, type_r::TypeRChip,
    type_sys::TypeSysChip, type_u::TypeUChip,
};
