use crate::{params::*, poly::Poly};



pub fn cbd2<const K: usize>(input: &[u8; kyber_eta1::<K>()*KYBER_N/4]) -> Poly<K> {
    let mut poly = Poly::<K>::zero();

    for i in 0..KYBER_N/8 {
        let t = u32::from_le_bytes(input[4*i..4*i+4].try_into().unwrap());
        let mut d = t & 0x5555_5555;
        d += (t >> 1) & 0x5555_5555;

        for j in 0..8 {
            let a = (d >> (4 * j + 0)) & 0x3;
            let b = (d >> (4*j +2)) & 0x3;
            poly.coeffs[8*i+j] = (a as i16) - (b as i16);
        }
    }
    poly
}


pub fn poly_cbd_eta1<const K: usize>(input: &[u8; kyber_eta1::<K>()*KYBER_N/4]) -> Poly<K> {
    if K == 2 {
        todo!("implement cbd3")
    } else {
        cbd2(input)
    }
}