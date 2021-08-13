//! Polynomial arithmetic

use crate::params::*;

/// Polynomial
pub struct Poly<const K: usize> {
    coeffs: [i16; KYBER_N],
}

impl<const K: usize> Poly<K> {
    pub const COMPRESSED_BYTES: usize = kyber_polycompressedbytes::<K>();

    /// Create a new empty polynomial
    pub(crate) fn new() -> Self {
        Poly {
            coeffs: [0; KYBER_N],
        }
    }

    /// Compression and serialization of a polynomial
    pub fn compress_into(&self, out: &mut [u8; Self::COMPRESSED_BYTES]) {
        let mut tmp = [0u8; 8];
        debug_assert!(Self::COMPRESSED_BYTES == 128 || Self::COMPRESSED_BYTES == 160);

        if Self::COMPRESSED_BYTES == 128 {
            for i in 0..(KYBER_N / 8) {
                for j in 0..8 {
                    // map to positive standard representation
                    let u = self.coeffs[8 * i + j];
                    let u = ((u >> 15) & KYBER_Q as i16) as u16;
                    tmp[j] = ((((u << 4) + (KYBER_Q as u16) / 2) / KYBER_Q as u16) as u8) & 15;
                }

                out[i * 4 + 0] = tmp[0] | (tmp[1] << 4);
                out[i * 4 + 1] = tmp[2] | (tmp[3] << 4);
                out[i * 4 + 2] = tmp[4] | (tmp[5] << 4);
                out[i * 4 + 3] = tmp[6] | (tmp[7] << 4);
            }
        } else {
            for i in 0..(KYBER_N / 8) {
                for j in 0..8 {
                    // map to positive standard representation
                    let u = self.coeffs[8 * i + j];
                    let u = ((u >> 15) & KYBER_Q as i16) as u16;
                    tmp[j] = ((((u << 5) + (KYBER_Q as u16) / 2) / KYBER_Q as u16) as u8) & 31;
                }

                out[i * 5 + 0] = (tmp[0] >> 0) | (tmp[1] << 5);
                out[i * 5 + 1] = (tmp[1] >> 3) | (tmp[2] << 2) | (tmp[3] << 7);
                out[i * 5 + 2] = (tmp[3] >> 1) | (tmp[4] << 4);
                out[i * 5 + 3] = (tmp[4] >> 4) | (tmp[5] << 1) | (tmp[6] << 6);
                out[i * 5 + 4] = (tmp[6] >> 2) | (tmp[7] << 3);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new() {
        let _ = Poly::<2>::new();
        let _ = Poly::<3>::new();
        let _ = Poly::<4>::new();
    }

    #[test]
    fn test_poly_compress() {
        let poly = Poly::<2>::new();
        let mut outbuf = [0u8; Poly::<2>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);

        let poly = Poly::<3>::new();
        let mut outbuf = [0u8; Poly::<3>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);

        let poly = Poly::<4>::new();
        let mut outbuf = [0u8; Poly::<4>::COMPRESSED_BYTES];
        poly.compress_into(&mut outbuf);
    }
}
