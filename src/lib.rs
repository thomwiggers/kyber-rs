#![allow(incomplete_features)]
#![allow(clippy::identity_op)]
#![feature(array_chunks, const_generics, const_evaluatable_checked)]
#![feature(maybe_uninit_uninit_array, maybe_uninit_array_assume_init, maybe_uninit_extra)]

mod utils;
pub(crate) use utils::*;

mod params;
mod poly;
mod polyvec;
mod indcpa;
pub mod kem;
