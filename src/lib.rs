#![allow(incomplete_features)]
#![allow(clippy::identity_op)]
#![feature(array_chunks, adt_const_params, generic_const_exprs)]
#![feature(
    maybe_uninit_uninit_array,
    maybe_uninit_array_assume_init,
    maybe_uninit_slice,
    maybe_uninit_write_slice
)]

mod utils;

mod indcpa;
pub mod kem;
mod params;
mod poly;
mod polyvec;
mod symmetric;
mod cbd;
mod reduce;
mod ntt;