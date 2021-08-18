use crate::{params::*, polyvec::PolyVec};

fn pack_pk<const K: usize>(
    pk: &PolyVec<K>,
    seed: &[u8; KYBER_SYMBYTES],
    output: &mut [u8; kyber_indcpa_pkbytes::<K>()],
) where
    [(); kyber_polyvec_bytes::<K>()]: Sized, // huh?
{
    // FIXME once https://github.com/rust-lang/rust/issues/74674 clarifies
    let (polypart, seedpart) = output.split_at_mut(kyber_polyvec_bytes::<K>());
    let polypart = polypart.try_into().unwrap();
    pk.to_bytes(polypart);

    seedpart.copy_from_slice(seed);
}
