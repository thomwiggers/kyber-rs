use std::mem::MaybeUninit;

use crate::{params::*, poly::Poly, polyvec::PolyVec, symmetric::*, utils::split_array};

/// Serialize the public key by concatinating the
/// polynomial vector pk with the seed for matrix A.
fn pack_pk<const K: usize>(
    pk: &PolyVec<K>,
    seed: &[u8; KYBER_SYMBYTES],
    output: &mut [u8; kyber_indcpa_pkbytes::<K>()], // https://hackmd.io/OZG_XiLFRs2Xmw5s39jRzA?view
) where
    [(); kyber_polyvec_bytes::<K>()]: , // huh?
{
    // FIXME once https://github.com/rust-lang/rust/issues/74674 clarifies
    let (polypart, seedpart) = output.split_at_mut(kyber_polyvec_bytes::<K>());
    let polypart = polypart.try_into().unwrap();
    pk.to_bytes(polypart);

    // copy seed
    seedpart.copy_from_slice(seed);
}

fn unpack_pk<const K: usize>(
    packed_pk: &[u8; kyber_indcpa_pkbytes::<K>()],
) -> (PolyVec<K>, [u8; KYBER_SYMBYTES])
where
    [(); kyber_polyvec_bytes::<K>()]: ,
{
    // FIXME once https://github.com/rust-lang/rust/issues/74674 clarifies
    let mut seed = MaybeUninit::uninit_array();
    let (polypart, seedpart) = packed_pk.split_at(kyber_polyvec_bytes::<K>());

    // deserialize pk
    let poly = PolyVec::<K>::from_bytes(polypart.try_into().unwrap());

    // initialize seed for matrix A
    MaybeUninit::write_slice(&mut seed, seedpart);

    let seed = unsafe { MaybeUninit::array_assume_init(seed) };

    (poly, seed)
}

/// Run rejection sampling on uniform random bytes to generate
/// uniform random integers mod q.
///
/// Parameters:
///    input: random data
///    r: buffer that we'll try to fill with as many uniformly random i16
///       as possible.
///
/// Returns the number of successfully
fn rej_uniform(input: &[u8], r: &mut [i16]) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < r.len() && pos + 3 >= input.len() {
        let val0 = ((input[pos+0] >> 0) as i16 | ((input[pos+1] as i16) << 8)) & 0xFFF;
        let val1 = ((input[pos+1] >> 4) as i16 | ((input[pos+2] as i16) << 4)) & 0xFFF;
        pos += 3;

        if val0 < KYBER_Q as i16 {
            r[ctr] = val0;
            ctr += 1;
        }
        if ctr < r.len() && val1 < KYBER_Q as i16 {
            r[ctr] = val1;
            ctr += 1;
        }
    }

    ctr
}

const XOF_BLOCKBYTES: usize = 168;

const GEN_MATRIX_NBLOCKS: usize =
    (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;

fn gen_matrix<const K: usize>(seed: &[u8; KYBER_SYMBYTES], transposed: bool) -> [PolyVec<K>; K] {
    let mut buffer = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut polys: [MaybeUninit<PolyVec<K>>; K] = MaybeUninit::uninit_array();
    for (i, polyvec) in polys.iter_mut().enumerate() {
        let mut new_polyvec = PolyVec::<K>::new();
        for (j, poly) in new_polyvec.vec.iter_mut().enumerate() {
            let mut xof = XofState::new();
            if transposed {
                xof.absorb(seed, i as u8, j as u8);
            } else {
                xof.absorb(seed, j as u8, i as u8);
            }

            let mut buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            xof.squeeze(&mut buffer[..buflen]);
            let mut sampled = rej_uniform(&buffer[..], &mut poly.coeffs[..]);
            while sampled < KYBER_N {
                let offset = buflen % 3;
                for k in 0..offset {
                    buffer[k] = buffer[buflen - offset + k];
                }
                xof.squeeze(&mut buffer[offset..XOF_BLOCKBYTES]);
                buflen = offset + XOF_BLOCKBYTES;
                sampled += rej_uniform(&buffer[0..buflen], &mut poly.coeffs[sampled..]);
            }
        }
        *polyvec = MaybeUninit::new(new_polyvec);
    }

    unsafe { MaybeUninit::array_assume_init(polys) }
}

fn gen_a<const K: usize>(seed: &[u8; KYBER_SYMBYTES]) -> [PolyVec<K>; K] {
    gen_matrix(seed, false)
}

fn gen_at<const K: usize>(seed: &[u8; KYBER_SYMBYTES]) -> [PolyVec<K>; K] {
    gen_matrix(seed, true)
}

pub(crate) struct IndcpaPublicKey<const K: usize>
where
    [(); kyber_indcpa_pkbytes::<K>()]: ,
{
    pk: [u8; kyber_indcpa_pkbytes::<K>()],
}
pub(crate) struct IndcpaSecretKey<const K: usize>
where
    [(); kyber_indcpa_skbytes::<K>()]: ,
{
    sk: [u8; kyber_indcpa_skbytes::<K>()],
}

pub(crate) fn indcpa_keypair<const K: usize>(
    seed: &[u8; KYBER_SYMBYTES],
) -> (IndcpaPublicKey<K>, IndcpaSecretKey<K>)
where
    [(); kyber_indcpa_skbytes::<K>()]: ,
    [(); kyber_indcpa_pkbytes::<K>()]: ,
    [(); kyber_eta1::<K>() * KYBER_N / 4]: ,
{
    let buf = hash_g(&seed[..]);
    let (publicseed, noiseseed): (&[u8; KYBER_SYMBYTES], &[u8]) = split_array(&buf);
    let noiseseed= noiseseed.try_into().unwrap();

    let matrix_a = gen_a::<K>(publicseed);

    let mut spkv = PolyVec::<K>::new();
    let mut nonce = 0;
    for poly in &mut spkv.vec {
        *poly = Poly::<K>::from_noise_eta1(noiseseed, nonce);
        nonce += 1;
    }
    let mut e = PolyVec::<K>::new();
    for poly in &mut e.vec {
        *poly = Poly::<K>::from_noise_eta1(noiseseed, nonce);
        nonce += 1;
    }

    spkv.ntt();
    e.ntt();

    let pk = IndcpaPublicKey {
        pk: [0; kyber_indcpa_pkbytes::<K>()],
    };
    let sk = IndcpaSecretKey {
        sk: [0; kyber_indcpa_skbytes::<K>()],
    };
    (pk, sk)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::utils::random_array;

    #[test]
    fn test_pack_unpack() {
        const K: usize = 3;
        let pk = PolyVec::<K>::random();
        let seed: [u8; KYBER_SYMBYTES] = random_array();

        let mut output = [0; kyber_indcpa_pkbytes::<K>()];
        pack_pk(&pk, &seed, &mut output);

        let (pk2, seed2) = unpack_pk(&output);

        assert_eq!(pk, pk2);
        assert_eq!(seed, seed2);
    }
}
