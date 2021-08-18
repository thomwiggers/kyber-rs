use crate::{params::*, polyvec::PolyVec, utils::split_array_mut};

fn pack_pk<const K: usize>(pk: &PolyVec<K>, seed: &[u8; KYBER_SYMBYTES], output: &mut [u8; kyber_indcpa_pkbytes::<K>()]) 
{
    // works because array_chunks works as split here
    // FIXME once https://github.com/rust-lang/rust/issues/74674 clarifies
    let (polypart, seedpart) = output.split_at_mut(kyber_polyvec_bytes::<K>());
    let polypart = unsafe { &mut *(polypart.as_mut_ptr() as *mut [u8; kyber_polyvec_bytes::<K>()])};
    pk.to_bytes(polypart);

    seedpart.copy_from_slice(seed);

}