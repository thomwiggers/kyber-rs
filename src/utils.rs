#[cfg(test)]
use rand::prelude::*;

// based on https://github.com/rust-lang/rust/pull/83233/files#diff-e8ccaf64ce21f955ccebef33b52158631493a6f0966815a2ebc142d7cd2b5e06R1671-R1677
pub fn split_array_mut<T, const N: usize, const M: usize>(arr: &mut [T; N]) -> (&mut [T; M], &mut [T]) {
    let (l, r) = arr.split_at_mut(M);
    unsafe { (&mut *(l.as_mut_ptr() as *mut [T; M]), r) }
}

#[cfg(test)]
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    thread_rng().fill_bytes(&mut buf);

    buf    
}