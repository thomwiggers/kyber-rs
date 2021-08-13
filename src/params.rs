//! Constants and functions to compute derived constants
#![allow(unused)]

/// N parameter in Kyber
pub const KYBER_N: usize = 256;

/// Q parameter in Kyber
pub const KYBER_Q: usize = 3329;

/// Size in bytes of hashes and seeds
pub const KYBER_SYMBYTES: usize = 32;

/// Size in bytes of shared key
pub const KYBER_SSBYTES: usize = 32;

/// Size of polynomial
pub const KYBER_POLYBYTES: usize = 384;

/// Size of a polynomial vector
pub const fn kyber_polyvecbytes<const K: usize>() -> usize {
    if K == 2 || K == 3 {
        320 * K
    } else if K == 4 {
        352 * K
    } else {
        0
    }
}

/// Size of compressed polynomial
pub const fn kyber_polycompressedbytes<const K: usize>() -> usize {
    if K == 2 || K == 3 {
        128
    } else {
        160
    }
}

/// Value of eta1 for this Kyber instance
pub const fn kyber_eta1<const K: usize>() -> usize {
    if K == 2 {
        3
    } else {
        2
    }
}

pub const KYBER_ETA2: usize = 2;
