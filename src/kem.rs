use crate::params::*;


/// Kyber Public Key
struct KyberPublicKey<const SIZE: usize>([u8; SIZE]);

struct KyberSecretKey<const SIZE: usize>([u8; SIZE]);

impl<const K: usize> AsRef<[u8]> for KyberPublicKey<K> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const K: usize> AsRef<[u8]> for KyberSecretKey<K> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct Ciphertext<const SIZE: usize>([u8; SIZE]);

pub struct SharedSecret([u8; KYBER_SSBYTES]);

pub mod kyber512 {
    use super::*;

    const K: usize = 2;
    const PK_BYTES: usize = K * KYBER_POLYBYTES * KYBER_SYMBYTES;
    const SK_BYTES: usize = K * KYBER_POLYBYTES;
    const CT_SIZE: usize = kyber_polyvec_compressed_bytes::<K>() + kyber_poly_compressed_bytes::<K>();

    pub struct PublicKey(KyberPublicKey<PK_BYTES>);
    pub struct SecretKey(KyberSecretKey<SK_BYTES>);

    pub fn keypair() -> Result<(PublicKey, SecretKey), ()> {
        // let pk = PublicKey(KyberPublicKey([0; PK_BYTES]));
        // let sk = SecretKey(KyberSecretKey([0; SK_BYTES]));
        Err(())
    }

    pub fn encaps(_pk: &PublicKey) -> Result<(Ciphertext<CT_SIZE>, SharedSecret), ()> {
        Err(())
    }

}