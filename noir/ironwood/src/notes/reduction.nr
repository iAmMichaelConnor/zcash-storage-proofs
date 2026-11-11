use bignum::BigNum;
use bignum::bignum::evaluate_quadratic_expression;
// This generic helper is deliberately limited to the two 255-bit Pasta primes.
// Input chunks have 240,240,32 bits; the one batched equation binds a canonical
// output to the full512-bit little-endian integer, without native Field packing.
#[no_predicates]
pub fn reduce512<T: BigNum>(bytes: [u8; 64]) -> T {
    assert(T::num_limbs(T::zero()) == 3);
    assert(T::modulus_bits(T::zero()) == 255);
    let modulus = T::params().modulus;
    assert(modulus[1] == 34);
    assert(modulus[2] == 16384);
    assert(
        (modulus[0] == 366563674732566411551322322153504769)
            | (modulus[0] == 366563674819230136617306365548822529),
    );
    let constants = {
        let mut limbs = T::zero().get_limbs();
        limbs[2] = 1;
        let c = T::from_limbs(limbs);
        [c, c * c]
    };
    let mut chunks = [T::zero(); 3];
    for i in 0..3 {
        let mut limbs = T::zero().get_limbs();
        for j in 0..30 {
            if i * 30 + j < 64 {
                let k = j / 15;
                limbs[k] = limbs[k] + ((bytes[i * 30 + j] as u128) << ((8 * (j % 15)) as u128));
            }
        }
        chunks[i] = T::from_limbs(limbs);
    }
    // Safety: output is canonical and the full batched modular relation is checked.
    let result = unsafe { reduce_hint(chunks, constants) };
    result.validate_in_range();
    result.validate_in_field();
    evaluate_quadratic_expression(
        [[chunks[1]], [chunks[2]]],
        [[false]; 2],
        [[constants[0]], [constants[1]]],
        [[false]; 2],
        [chunks[0], result],
        [false, true],
    );
    result
}
unconstrained fn reduce_hint<T: BigNum>(chunks: [T; 3], constants: [T; 2]) -> T {
    chunks[0].__add(&chunks[1].__mul(&constants[0])).__add(&chunks[2].__mul(&constants[1]))
}
