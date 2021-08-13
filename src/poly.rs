//! Polynomial arithmetic

use std::{
    intrinsics::transmute,
    mem::MaybeUninit,
    ops::{Add, AddAssign, Sub, SubAssign},
};

#[cfg(test)]
use rand::prelude::*;

use crate::params::*;

/// Polynomial
#[derive(Debug, PartialEq, Clone)]
pub struct Poly<const K: usize> {
    coeffs: [i16; KYBER_N],
}

fn positive_repr(p: i16) -> u16 {
    let result = p + ((p >> 15) & KYBER_Q as i16);
    debug_assert!(result >= 0 && result < KYBER_Q as i16);
    result as u16
}

impl<const K: usize> Poly<K> {
    pub const COMPRESSED_BYTES: usize = kyber_polycompressedbytes::<K>();

    /// Create a new empty polynomial
    pub(crate) fn zero() -> Self {
        Poly {
            coeffs: [0; KYBER_N],
        }
    }

    /// Initialize a random polynomial
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        let mut poly = Self::zero();
        rand::thread_rng().fill(&mut poly.coeffs);
        poly.coeffs
            .iter_mut()
            .for_each(|el| *el = (*el as u16 % KYBER_Q as u16) as i16);
        poly
    }

    /// Serialize a polynomial
    pub fn to_bytes(&self, out: &mut [u8; KYBER_POLYBYTES]) {
        for i in 0..KYBER_N / 2 {
            let t0 = positive_repr(self.coeffs[2 * i]);
            let t1 = positive_repr(self.coeffs[2 * i + 1]);
            out[3 * i + 0] = t0 as u8;
            out[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
            out[3 * i + 2] = (t1 >> 4) as u8;
        }
    }

    /// Deserialize a polynomial
    pub fn from_bytes(input: &[u8; KYBER_POLYBYTES]) -> Self {
        let mut poly = Self::zero();
        for i in 0..KYBER_N / 2 {
            poly.coeffs[2 * i + 0] =
                (input[3 * i + 0] >> 0) as i16 | (((input[3 * i + 1] as i16) << 8) & 0xFFF);
            poly.coeffs[2 * i + 1] =
                (input[3 * i + 1] >> 4) as i16 | (((input[3 * i + 2] as i16) << 4) & 0xFFF);
        }
        poly
    }

    /// Compression and serialization of a polynomial
    pub fn compress_into(&self, out: &mut [u8; Self::COMPRESSED_BYTES]) {
        let mut tmp = [0u8; 8];
        debug_assert!(Self::COMPRESSED_BYTES == 128 || Self::COMPRESSED_BYTES == 160);

        if Self::COMPRESSED_BYTES == 128 {
            for i in 0..(KYBER_N / 8) {
                #[allow(clippy::needless_range_loop)]
                for j in 0..8 {
                    // map to positive standard representation
                    const Q: u32 = KYBER_Q as u32;
                    let u = positive_repr(self.coeffs[8 * i + j]) as u32;
                    let u = (((u << 4) + Q / 2) / Q) & 15;
                    tmp[j] = u as u8;
                }

                out[i * 4 + 0] = tmp[0] | (tmp[1] << 4);
                out[i * 4 + 1] = tmp[2] | (tmp[3] << 4);
                out[i * 4 + 2] = tmp[4] | (tmp[5] << 4);
                out[i * 4 + 3] = tmp[6] | (tmp[7] << 4);
            }
        } else {
            for i in 0..(KYBER_N / 8) {
                #[allow(clippy::needless_range_loop)]
                for j in 0..8 {
                    // map to positive standard representation
                    const Q: u32 = KYBER_Q as u32;
                    let u = positive_repr(self.coeffs[8 * i + j]) as u32;
                    let u = (((u << 5) + Q / 2) / Q) & 31;
                    tmp[j] = u as u8;
                }

                out[i * 5 + 0] = (tmp[0] >> 0) | (tmp[1] << 5);
                out[i * 5 + 1] = (tmp[1] >> 3) | (tmp[2] << 2) | (tmp[3] << 7);
                out[i * 5 + 2] = (tmp[3] >> 1) | (tmp[4] << 4);
                out[i * 5 + 3] = (tmp[4] >> 4) | (tmp[5] << 1) | (tmp[6] << 6);
                out[i * 5 + 4] = (tmp[6] >> 2) | (tmp[7] << 3);
            }
        }
    }

    /// De-serialize and decompress a polynomial
    ///
    /// **Approximate** inverse of `compress_into`
    pub fn decompress(buf: &[u8; Self::COMPRESSED_BYTES]) -> Self {
        debug_assert!(Self::COMPRESSED_BYTES == 128 || Self::COMPRESSED_BYTES == 160);

        let mut out = Self::zero();

        if Self::COMPRESSED_BYTES == 128 {
            #[allow(clippy::needless_range_loop)]
            for i in 0..KYBER_N / 2 {
                let a = (((buf[i] & 15) as u32 * KYBER_Q as u32 + 8) >> 4) as i16;
                let b = (((buf[i] >> 4) as u32 * KYBER_Q as u32 + 8) >> 4) as i16;
                out.coeffs[2 * i + 0] = a;
                out.coeffs[2 * i + 1] = b;
            }
        } else {
            let mut tmp = [0u8; 8];
            #[allow(clippy::needless_range_loop)]
            for i in 0..KYBER_N / 8 {
                tmp[0] = buf[5 * i + 0] >> 0;
                tmp[1] = (buf[5 * i + 0] >> 5) | (buf[5 * i + 1] << 3);
                tmp[2] = buf[5 * i + 1] >> 2;
                tmp[3] = (buf[5 * i + 1] >> 7) | (buf[5 * i + 2] << 1);
                tmp[4] = (buf[5 * i + 2] >> 4) | (buf[5 * i + 3] << 4);
                tmp[5] = buf[5 * i + 3] >> 1;
                tmp[6] = (buf[5 * i + 3] >> 6) | (buf[5 * i + 4] << 2);
                tmp[7] = buf[5 * i + 4] >> 3;

                #[allow(clippy::needless_range_loop)]
                for j in 0..8 {
                    out.coeffs[8 * i + j] =
                        ((((tmp[j] & 31) as u32 * KYBER_Q as u32) + 16) >> 5) as i16
                }
            }
        }

        out
    }
}

// All the arithmetic implementations follow.
// This is a bit of a messiness in Rust.
// We're implementing all possible combinations of &Poly $op Poly
// while avoiding every possible alloc.

macro_rules! poly_binary_op {
    ($self: ident, $rhs: ident, $operation: tt) => {{
        // This follows the exmaple from MaybeUninit
        // This is safe because initializing MaybeUninits isn't necessary
        let mut coeffs: [MaybeUninit<i16>; KYBER_N] =
            unsafe { MaybeUninit::uninit().assume_init() };
        // this will generate all the new result items
        let resultiter = $self
            .coeffs
            .iter()
            .zip($rhs.coeffs.iter())
            .map(|(l, r)| l $operation r);
        // The maybeuninits are safe to drop, because dropping a maybeuninit is a no-op.
        coeffs
            .iter_mut()
            .zip(resultiter)
            .for_each(|(dest, src)| *dest = MaybeUninit::new(src));
        // Everything is initialized now, so we can transmute into the final item.
        let coeffs: [i16; KYBER_N] = unsafe { transmute(coeffs) };

        Poly { coeffs }
    }}
}

impl<const K: usize> Add for &Poly<K> {
    type Output = Poly<K>;

    fn add(self, rhs: Self) -> Self::Output {
        poly_binary_op!(self, rhs, +)
    }
}

impl<const K: usize> Add<&Poly<K>> for Poly<K> {
    type Output = Poly<K>;

    fn add(mut self, rhs: &Poly<K>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const K: usize> Add<Poly<K>> for &Poly<K> {
    type Output = Poly<K>;

    fn add(self, mut rhs: Poly<K>) -> Self::Output {
        rhs.coeffs
            .iter_mut()
            .zip(self.coeffs.iter().copied())
            .for_each(|(r, l)| *r = l + *r);
        rhs
    }
}

impl<const K: usize> Add for Poly<K> {
    type Output = Poly<K>;

    fn add(mut self, rhs: Poly<K>) -> Self::Output {
        self += rhs;
        self
    }
}

impl<const K: usize> AddAssign<&Poly<K>> for Poly<K> {
    fn add_assign(&mut self, rhs: &Self) {
        self.coeffs
            .iter_mut()
            .zip(rhs.coeffs.iter().copied())
            .for_each(|(dst, src)| *dst += src);
    }
}

impl<const K: usize> AddAssign for Poly<K> {
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs;
    }
}

impl<const K: usize> Sub for &Poly<K> {
    type Output = Poly<K>;

    fn sub(self, rhs: Self) -> Self::Output {
        poly_binary_op!(self, rhs, -)
    }
}

impl<const K: usize> Sub for Poly<K> {
    type Output = Poly<K>;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const K: usize> Sub<&Poly<K>> for Poly<K> {
    type Output = Poly<K>;

    fn sub(mut self, rhs: &Poly<K>) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<const K: usize> Sub<Poly<K>> for &Poly<K> {
    type Output = Poly<K>;

    fn sub(self, mut rhs: Poly<K>) -> Self::Output {
        rhs.coeffs
            .iter_mut()
            .zip(self.coeffs.iter().copied())
            .for_each(|(r, l)| *r = l - *r);
        rhs
    }
}

impl<const K: usize> SubAssign<&Poly<K>> for Poly<K> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.coeffs
            .iter_mut()
            .zip(rhs.coeffs.iter().copied())
            .for_each(|(dst, src)| *dst -= src);
    }
}

impl<const K: usize> SubAssign<Poly<K>> for Poly<K> {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // adapted from Circl https://github.com/cloudflare/circl/blob/62142fc919e58fc8d1d745cfd67f23c62020d6ee/pke/kyber/internal/common/poly_test.go#L18
    fn s_mod_q(x: i16) -> i16 {
        const Q: i16 = KYBER_Q as i16;
        let x = x % Q;
        if x >= (Q - 1) / 2 {
            x - Q
        } else {
            x
        }
    }

    #[test]
    fn test_new() {
        let _ = Poly::<2>::zero();
        let _ = Poly::<3>::zero();
        let _ = Poly::<4>::zero();
    }

    #[test]
    fn test_poly_compress_calls() {
        let poly = Poly::<2>::zero();
        let mut outbuf = [0u8; Poly::<2>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);

        let poly = Poly::<3>::zero();
        let mut outbuf = [0u8; Poly::<3>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);

        let poly = Poly::<4>::zero();
        let mut outbuf = [0u8; Poly::<4>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);
    }

    /// Test compression followed by decompression for K=2
    ///
    /// Based on https://github.com/cloudflare/circl/blob/62142fc919e58fc8d1d745cfd67f23c62020d6ee/pke/kyber/internal/common/poly_test.go#L44-L69
    #[test]
    fn test_compress_decompress_2() {
        let poly = Poly::<2>::random();
        let mut outbuf = [0u8; Poly::<2>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);
        println!("{:x?}", outbuf);
        let poly2 = Poly::<2>::decompress(&outbuf);

        for (l, r) in poly
            .coeffs
            .iter()
            .copied()
            .zip(poly2.coeffs.iter().copied())
        {
            const BOUND: u16 = (KYBER_Q as u16 + 1 << 4) >> 5;

            let diff = s_mod_q(l - r).abs() as u16;
            assert!(
                diff < BOUND,
                "|{} - {} mod^± q| = {} > {}",
                l,
                r,
                diff,
                BOUND
            );
        }
    }

    /// Test compression followed by decompression for K=4
    ///
    /// Based on https://github.com/cloudflare/circl/blob/62142fc919e58fc8d1d745cfd67f23c62020d6ee/pke/kyber/internal/common/poly_test.go#L44-L69
    #[test]
    fn test_compress_decompress_4() {
        let poly = Poly::<4>::random();
        let mut outbuf = [0u8; Poly::<4>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);
        println!("{:x?}", outbuf);
        let poly2 = Poly::<4>::decompress(&outbuf);

        for (l, r) in poly
            .coeffs
            .iter()
            .copied()
            .zip(poly2.coeffs.iter().copied())
        {
            const BOUND: u16 = (KYBER_Q as u16 + 1 << 5) >> 6;

            let diff = s_mod_q(l - r).abs() as u16;
            assert!(
                diff < BOUND,
                "|{} - {} mod^± q| = {} > {}",
                l,
                r,
                diff,
                BOUND
            );
        }
    }

    /// Some arithmetic tests
    #[test]
    fn test_arithmetic() {
        let zeros = Poly::<2>::zero();
        let random = Poly::<2>::zero();

        assert_eq!(random, &random + &zeros);
        assert_eq!(random, &random - &zeros);
        assert_eq!(random, &zeros + &random - &random);
        assert_eq!(zeros, &random - &random);
        assert_eq!(random, &random - &zeros);
        assert_eq!(random, &random - zeros);
    }

    /// Test serialization and deserialization of polynomials.
    #[test]
    fn test_serialization() {
        let start = Poly::<2>::random();
        let mut out = [0u8; KYBER_POLYBYTES];
        start.to_bytes(&mut out);
        let poly2 = Poly::<2>::from_bytes(&out);
        assert_eq!(start, poly2);
    }
}
