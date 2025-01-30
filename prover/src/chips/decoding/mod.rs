// This module contains chips about instruction decoding.

mod type_b;
mod type_i;
mod type_j;
mod type_r;
mod type_s;
mod type_sys;
mod type_u;

pub type DecodingCheckChip = (
    type_r::TypeRChip,
    type_i::TypeIChip,
    type_s::TypeSChip,
    type_b::TypeBChip,
    type_u::TypeUChip,
    type_j::TypeJChip,
    type_sys::TypeSysChip,
);
