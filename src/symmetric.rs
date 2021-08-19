use digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3XofReader, Sha3_256, Sha3_512, Shake128};
use sha3::{Digest};

use crate::params::KYBER_SYMBYTES;

pub fn hash_h(buffer: &[u8]) -> [u8; 32] {
    let digest = Sha3_256::digest(buffer);
    digest.as_slice().try_into().unwrap()
  
}

pub fn hash_g(buffer: &[u8]) -> [u8; 64] {
    let digest = Sha3_512::digest(&buffer);
    digest.as_slice().try_into().unwrap()
}

pub(crate) struct XofState(XofStateVariant);

enum XofStateVariant {
    Absorb(Shake128),
    Squeeze(Sha3XofReader),
}

impl XofStateVariant {
    fn finalize(&mut self) {
        if let XofStateVariant::Absorb(xof) = self {
            *self = XofStateVariant::Squeeze(xof.clone().finalize_xof());
        }
    }
}

impl XofState {
    pub fn new() -> Self {
        XofState(XofStateVariant::Absorb(Shake128::default()))
    }

    pub fn absorb(&mut self, data: &[u8; KYBER_SYMBYTES], x: u8, y: u8) {
        let xof = match &mut self.0 {
           XofStateVariant::Absorb(xof) => xof,
           _ => panic!("Can't absorb if you've already finalized!"),
        };

        let mut buf = [0u8; KYBER_SYMBYTES+2];
        buf[..KYBER_SYMBYTES].copy_from_slice(&data[..]);
        buf[KYBER_SYMBYTES] = x;
        buf[KYBER_SYMBYTES] = y;

        xof.update(&buf);
    }

    /// Squeeze out output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.0.finalize();
        let xof = match &mut self.0 {
            XofStateVariant::Squeeze(xof) => xof,
            _ => panic!("Finalize first"),
        };

        xof.read(output);
    }
}

#[cfg(test)]

mod test {
    use crate::utils::random_array;

    use super::*;

    #[test]
    fn test_hashes() {
        let data = random_array::<10>();

        hash_h(&data[..]);
        hash_g(&data[..]);
    }
}