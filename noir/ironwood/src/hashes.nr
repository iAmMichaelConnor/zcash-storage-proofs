pub mod blake2b;
// Fixed length, personalized BLAKE2b. Digest length changes the parameter block;
// BLAKE2b-256 is not a truncation of a BLAKE2b-512 invocation.
pub fn hash<let N: u32, let OUT: u32>(message: [u8; N], personalization: [u8; 16]) -> [u8; OUT] {
    let mut h = blake2b::Blake2b::new_personalized::<OUT>(personalization);
    h.update_at::<0, N>(message);
    let full = h.finalize_at::<N>();
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        out[i] = full[i];
    }
    out
}

// Hash only a prefix whose endpoint stays in the final block of the N-byte
// buffer: floor((N-1)/128)*128 < length <= N. Every unused byte must be zero.
// This keeps compression boundaries static without accepting arbitrary padding.
pub fn hash_variable_last_block<let N: u32, let OUT: u32>(
    message: [u8; N],
    length: u32,
    personalization: [u8; 16],
) -> [u8; OUT] {
    let mut h = blake2b::Blake2b::new_personalized::<OUT>(personalization);
    h.update_at::<0, N>(message);
    let full = h.finalize_last_block_at::<N>(length);
    let mut out = [0u8; OUT];
    for i in 0..OUT {
        out[i] = full[i];
    }
    out
}
// General bounded message length, including empty and exact-block inputs.
// Inactive bytes must be zero; the circuit schedules ceil(N/128) compressions.
pub fn hash_bounded<let N: u32, let OUT: u32>(
    message: [u8; N],
    length: u32,
    personalization: [u8; 16],
) -> [u8; OUT] {
    blake2b::hash_bounded(message, length, personalization)
}
