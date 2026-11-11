//! Pinned Orchard/Ironwood PRF_nf: Poseidon P128Pow5T3, ConstantLength<2>.
//! Full field inputs use canonical 120/120/15-bit limbs, never a native Field.
mod constants;
use bignum::{BigNum, Pallas_Fq as Fq};
use bignum::bignum::evaluate_quadratic_expression;

// Evaluate sum_i (sum_j lhs[i][j]) * (sum_k rhs[i][k]) modulo the
// Pallas base prime. Every caller supplies canonical field operands. These
// small shapes have maximum cost12: the fused square has cost4 and the
// three-term MDS dot product cost6. The checked BigNum API range-checks
// the operands, quotient and carries; the result is explicitly canonical.
#[no_predicates]
fn quadratic<let N: u32, let L: u32, let R: u32>(lhs: [[Fq; L]; N], rhs: [[Fq; R]; N]) -> Fq {
    // Safety: canonical output and the complete modular equation are constrained below.
    let out = unsafe { quadratic_hint(lhs, rhs) };
    out.validate_in_range();
    out.validate_in_field();
    evaluate_quadratic_expression(lhs, [[false; L]; N], rhs, [[false; R]; N], [out], [true]);
    out
}
unconstrained fn quadratic_hint<let N: u32, let L: u32, let R: u32>(
    lhs: [[Fq; L]; N],
    rhs: [[Fq; R]; N],
) -> Fq {
    let mut out = Fq::zero();
    for i in 0..N {
        let mut a = Fq::zero();
        let mut b = Fq::zero();
        for j in 0..L {
            a = a.__add(&lhs[i][j]);
        }
        for j in 0..R {
            b = b.__add(&rhs[i][j]);
        }
        out = out.__add(&a.__mul(&b));
    }
    out
}
fn pow5_shifted(x: Fq, c: Fq) -> Fq {
    let x2 = quadratic([[x, c]], [[x, c]]);
    let x4 = quadratic([[x2]], [[x2]]);
    quadratic([[x4]], [[x, c]])
}
#[no_predicates]
pub fn hash2(a: Fq, b: Fq) -> Fq {
    a.validate_in_range();
    a.validate_in_field();
    b.validate_in_range();
    b.validate_in_field();
    // ConstantLength<2> capacity is input_length <<64, in state[rate].
    let mut state = [a, b, Fq::from_limbs([36893488147419103232, 0, 0])];
    let rc = comptime { constants::round_constants() };
    let mds = comptime { constants::mds() };
    for round in 0..64 {
        let full = (round < 4) | (round >= 60);
        let mut words = [[Fq::zero(); 2]; 3];
        for j in 0..3 {
            words[j] = if full | (j == 0) {
                [pow5_shifted(state[j], rc[round][j]), Fq::zero()]
            } else {
                [state[j], rc[round][j]]
            };
        }
        let mut next = [Fq::zero(); 3];
        for j in 0..3 {
            next[j] = quadratic(words, [[mds[j][0]], [mds[j][1]], [mds[j][2]]]);
        }
        state = next;
    }
    state[0]
}
