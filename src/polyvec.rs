use std::mem::MaybeUninit;

///! Polynomial vectors
use crate::{
    params::*,
    poly::Poly,
};

#[derive(Debug, PartialEq)]
pub struct PolyVec<const K: usize> {
    vec: [Poly<K>; K],
}

impl<const K: usize> PolyVec<K> {
    pub(crate) const POLYVECBYTES: usize = K * KYBER_POLYBYTES;

    #[cfg(test)]
    fn random() -> Self {
        let mut vec = MaybeUninit::uninit_array();
        for poly in vec.iter_mut() {
            *poly = MaybeUninit::new(Poly::<K>::random());
        }

        let vec = unsafe { MaybeUninit::array_assume_init(vec) };
        PolyVec { vec }
    }

    pub fn to_bytes(&self, out: &mut [u8; kyber_polyvec_bytes::<K>()]) {
        self.vec
            .iter()
            .zip(out.array_chunks_mut::<KYBER_POLYBYTES>())
            .for_each(|(vec, outbuf)| vec.to_bytes(outbuf));
    }

    pub fn from_bytes(input: &[u8; kyber_polyvec_bytes::<K>()]) -> Self {
        let mut vec = MaybeUninit::uninit_array();
        for (poly, bytes) in vec.iter_mut().zip(input.array_chunks::<KYBER_POLYBYTES>()) {
            *poly = MaybeUninit::new(Poly::from_bytes(bytes));
        }

        let vec = unsafe { MaybeUninit::array_assume_init(vec) };
        PolyVec { vec }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_from_bytes() {
        let pv = PolyVec::<3>::random();
        let mut outbuf = [0u8; {3 * KYBER_POLYBYTES}];

        pv.to_bytes(&mut outbuf)    ;
        let pv2 = PolyVec::<3>::from_bytes(&outbuf);
        assert_eq!(pv, pv2); 
    }
}
