use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
use bignum::bignum::evaluate_quadratic_expression;
use crate::sinsemilla::canonical;
use crate::memo::constants::{iso_a, isogeny};

// Exact pasta_curves 0.6.1 XMD BLAKE2b / simplified SWU / degree-three isogeny.
// https://docs.rs/pasta_curves/0.6.1/src/pasta_curves/hashtocurve.rs.html
// Affine formulas below trade speed for explicit complete exceptional handling.
// All comparisons and signs use canonical coordinates, never lazy aliases.
struct IsoPoint {
    pub x: Fq,
    pub y: Fq,
    pub infinity: bool,
}
fn fq(n: Field) -> Fq {
    Fq::from(n)
}
fn equal(a: Fq, b: Fq) -> bool {
    canonical(a);
    canonical(b);
    a.get_limbs() == b.get_limbs()
}
fn curve_y2(x: Fq) -> Fq {
    x * x * x + iso_a() * x + fq(1265)
}
fn odd(x: Fq) -> bool {
    canonical(x);
    (x.get_limbs()[0] & 1) == 1
}
// Exact division by a nonzero canonical denominator (< p). It is zero exactly
// when its limb sum (< 2^122, no native-field wraparound) is zero. The quotient
// is constrained by the checked quadratic relation below.
fn divide(numerator: Fq, denominator: Fq) -> Fq {
    // Safety: divide_with_quotient constrains the quotient.
    let quotient = unsafe { numerator.__div(&denominator) };
    divide_with_quotient(numerator, denominator, quotient)
}
fn divide_with_quotient(numerator: Fq, denominator: Fq, quotient: Fq) -> Fq {
    canonical(denominator);
    let limbs = denominator.get_limbs();
    assert(limbs[0] as Field + limbs[1] as Field + limbs[2] as Field != 0, "Zero denominator");
    // quotient * denominator - numerator = 0 (mod p), every term range checked.
    evaluate_quadratic_expression(
        [[quotient]],
        [[false]],
        [[denominator]],
        [[false]],
        [numerator],
        [true],
    );
    quotient
}

// Root evidence proves BOTH branches: if gx1 is not a square, Z*gx1 must
// be a nonzero square. Z=-13 is a fixed nonsquare in the Pallas base field.
// Thus a prover cannot choose the other SWU branch for a square gx1.
// The selected point's curve equation and sign are checked independently.
// `square` and `y` are unique. `nonsquare_root` is a certificate without a
// sign check: both square roots of Z*gx1 pass, and neither reaches the output.
fn swu_with_hints(u: Fq, square: bool, y: Fq, nonsquare_root: Fq) -> IsoPoint {
    canonical(u);
    canonical(y);
    canonical(nonsquare_root);
    let z = -fq(13);
    let zu2 = z * u * u;
    let ta = zu2 * zu2 + zu2;
    let denominator = iso_a() * (if equal(ta, Fq::zero()) { z } else { -ta });
    // For ta=0, use AZ, not inversion of zero. A,Z are fixed nonzero constants.
    let x1 = divide(fq(1265) * (ta + fq(1)), denominator);
    let gx1 = curve_y2(x1);
    let x = if square { x1 } else { zu2 * x1 };
    let gx = curve_y2(x);
    assert(equal(y * y, gx), "SWU selected root mismatch");
    assert(odd(y) == odd(u), "SWU root sign mismatch");
    if square {
        assert(equal(nonsquare_root, Fq::zero()), "Unexpected nonsquare witness");
    } else {
        assert(!equal(gx1, Fq::zero()), "Zero belongs to square SWU branch");
        assert(equal(nonsquare_root * nonsquare_root, z * gx1), "SWU branch mismatch");
    }
    IsoPoint { x, y, infinity: false }
}
unconstrained fn swu_hint(u: Fq) -> (bool, Fq, Fq) {
    let z = -fq(13);
    let zu2 = z * u * u;
    let ta = zu2 * zu2 + zu2;
    let x1 = fq(1265) * (ta + fq(1)) / (iso_a() * (if ta.is_zero() { z } else { -ta }));
    let root = curve_y2(x1).__sqrt();
    let square = root.is_some();
    let x = if square { x1 } else { zu2 * x1 };
    let mut y = curve_y2(x).__sqrt().unwrap();
    if odd(y) != odd(u) {
        y = -y;
    }
    let proof = if square {
        Fq::zero()
    } else {
        (z * curve_y2(x1)).__sqrt().unwrap()
    };
    (square, y, proof)
}
fn swu(u: Fq) -> IsoPoint {
    // Safety: swu_with_hints constrains the branch choice and y uniquely; the
    // sign of the nonsquare-branch certificate is free and does not reach the output.
    let (square, y, proof) = unsafe { swu_hint(u) };
    swu_with_hints(u, square, y, proof)
}
// Complete group addition on the isogenous curve y^2=x^3+A*x+1265.
// Opposite/equal/infinity inputs remain valid. The inactive denominator is one.
fn iso_add(p: IsoPoint, q: IsoPoint) -> IsoPoint {
    let same_x = equal(p.x, q.x);
    let same_y = equal(p.y, q.y);
    let doubling = same_x & same_y;
    let active = !p.infinity & !q.infinity & (!same_x | (same_y & !equal(p.y, Fq::zero())));
    let numerator = if doubling {
        fq(3) * p.x * p.x + iso_a()
    } else {
        q.y - p.y
    };
    let denominator = if active {
        if doubling {
            fq(2) * p.y
        } else {
            q.x - p.x
        }
    } else {
        fq(1)
    };
    let slope = divide(numerator, denominator);
    let x = slope * slope - p.x - q.x;
    let y = slope * (p.x - x) - p.y;
    if p.infinity {
        q
    } else if q.infinity {
        p
    } else if active {
        IsoPoint { x, y, infinity: false }
    } else {
        IsoPoint { x: Fq::zero(), y: Fq::zero(), infinity: true }
    }
}
fn iso_map(p: IsoPoint) -> Pallas {
    let c = isogeny();
    let x = p.x;
    let y = p.y;
    let nx = ((c[0] * x + c[1]) * x + c[2]) * x + c[3];
    let dx = (x + c[4]) * x + c[5];
    let ny = (((c[6] * x + c[7]) * x + c[8]) * x + c[9]) * y;
    let dy = ((x + c[10]) * x + c[11]) * x + c[12];
    let identity = p.infinity | equal(dx, Fq::zero()) | equal(dy, Fq::zero());
    let outx = divide(nx, if identity { fq(1) } else { dx });
    let outy = divide(ny, if identity { fq(1) } else { dy });
    if identity {
        Pallas::point_at_infinity()
    } else {
        Pallas::from_coordinates(outx, outy, false)
    }
}
fn hash_fields<let N: u32>(message: [u8; N]) -> [Fq; 2] {
    let dst = "z.cash:Orchard-gd-pallas_XMD:BLAKE2b_SSWU_RO_".as_bytes();
    let mut first = [0u8; 128 + N + 3 + 46];
    for i in 0..N {
        first[128 + i] = message[i];
    }
    first[128 + N + 1] = 128;
    for i in 0..45 {
        first[128 + N + 3 + i] = dst[i];
    }
    first[128 + N + 3 + 45] = 45;
    let b0 = crate::hashes::hash::<128 + N + 3 + 46, 64>(first, [0u8; 16]);
    let mut second = [0u8; 111];
    for i in 0..64 {
        second[i] = b0[i];
    }
    second[64] = 1;
    for i in 0..45 {
        second[65 + i] = dst[i];
    }
    second[110] = 45;
    let b1 = crate::hashes::hash::<111, 64>(second, [0u8; 16]);
    for i in 0..64 {
        second[i] = b0[i] ^ b1[i];
    }
    second[64] = 2;
    let b2 = crate::hashes::hash::<111, 64>(second, [0u8; 16]);
    let mut rev1 = [0u8; 64];
    let mut rev2 = [0u8; 64];
    for i in 0..64 {
        rev1[i] = b1[63 - i];
        rev2[i] = b2[63 - i];
    }
    [crate::notes::reduction::reduce512(rev1), crate::notes::reduction::reduce512(rev2)]
}
pub fn hash_to_curve<let N: u32>(message: [u8; N]) -> Pallas {
    let u = hash_fields(message);
    iso_map(iso_add(swu(u[0]), swu(u[1])))
}
// Orchard substitutes hash(empty) if hash(diversifier) is the identity.
// Computing both constrained branches avoids narrowing that accepted domain.
pub fn diversify_hash(d: [u8; 11]) -> Pallas {
    let p = hash_to_curve(d);
    let fallback = hash_to_curve::<0>([]);
    replace_identity(p, fallback)
}
pub fn verify_raw_receiver(raw: [u8; 43], receiver: crate::notes::ExpandedReceiver) {
    let mut d = [0u8; 11];
    let mut pkd = [0u8; 32];
    for i in 0..11 {
        d[i] = raw[i];
    }
    for i in 0..32 {
        pkd[i] = raw[11 + i];
    }
    assert(crate::notes::encode_nonidentity(receiver.pk_d) == pkd, "Raw receiver pk_d mismatch");
    let derived = diversify_hash(d);
    assert(
        crate::notes::encode_nonidentity(receiver.g_d) == crate::notes::encode_nonidentity(derived),
        "Raw receiver diversifier mismatch",
    );
}

#[test]
fn swu_zero_and_small_inputs() {
    for i in 0..8 {
        let u = std::hint::black_box(fq(i as Field));
        let p = swu(u);
        assert(equal(p.y * p.y, curve_y2(p.x)));
        assert(odd(p.y) == odd(u));
    }
}
#[test]
fn isogenous_addition_accepts_equal_opposite_and_identity() {
    let p = swu(std::hint::black_box(fq(1)));
    let id = IsoPoint { x: Fq::zero(), y: Fq::zero(), infinity: true };
    let neg = IsoPoint { x: p.x, y: -p.y, infinity: false };
    assert(iso_add(p, neg).infinity);
    assert(equal(iso_add(p, id).x, p.x));
    assert(equal(iso_add(id, p).y, p.y));
    let doubled = iso_add(p, p);
    assert(!doubled.infinity);
    assert(equal(doubled.y * doubled.y, curve_y2(doubled.x)));
    assert(iso_map(id).is_infinity());
    assert(iso_map(iso_add(p, neg)).is_infinity());
}
#[test(should_fail_with = "SWU root sign mismatch")]
fn rejects_opposite_swu_sign() {
    let u = std::hint::black_box(fq(1));
    // Safety: malicious hints intentionally exercise the constrained checker.
    let (square, y, proof) = unsafe { swu_hint(u) };
    let _ = swu_with_hints(u, square, -y, proof);
}
// Even square root of B = 1265: the y root at x = Z*u^2*x1 = 0 for u = 0, whose
// honest branch is square (Tonelli-Shanks modulo the Pallas base field).
fn forged_swu_branch_root() -> Fq {
    Fq::from_limbs([
        1180618713369509205778296123764615748,
        221627696857313333163689875275667040,
        10616,
    ])
}
// The forged nonsquare-branch witness passes the root and sign checks, so only
// the branch certificate rejects it. Honest hints with square = false fail
// earlier at the root check and would not detect a deleted branch check.
#[test(should_fail_with = "SWU branch mismatch")]
fn rejects_forged_swu_branch() {
    let u = std::hint::black_box(fq(0));
    let y = std::hint::black_box(forged_swu_branch_root());
    let _ = swu_with_hints(u, false, y, std::hint::black_box(Fq::zero()));
}
// y = p (the modulus) fails the in-field check of canonical(y): p - y is zero.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn rejects_noncanonical_swu_root() {
    let q = Fq::params().modulus;
    let _ = swu_with_hints(fq(0), true, Fq::from_limbs_unsafe(q), Fq::zero());
}

fn replace_identity(p: Pallas, fallback: Pallas) -> Pallas {
    if p.is_infinity() {
        fallback
    } else {
        p
    }
}
#[test]
fn identity_diversifier_substitution_is_not_rejection() {
    let fallback = iso_map(swu(fq(1)));
    assert(!fallback.is_infinity());
    let output = replace_identity(std::hint::black_box(Pallas::point_at_infinity()), fallback);
    assert(equal(output.x, fallback.x));
    assert(equal(output.y, fallback.y));
    let unchanged = replace_identity(fallback, Pallas::point_at_infinity());
    assert(equal(unchanged.x, fallback.x));
}

// r = BN254 scalar modulus. r, p - r and 2r - p are nonzero Pallas elements
// whose native-field encodings alias 0, -p and p, respectively.
fn bn254_alias_denominators() -> [Fq; 3] {
    let r = std::hint::black_box(fq(-1)) + fq(1);
    [r, -r, r + r]
}
#[test]
fn divide_accepts_bn254_alias_denominators() {
    let numerator = std::hint::black_box(fq(1265));
    let aliases = bn254_alias_denominators();
    for i in 0..3 {
        let d = aliases[i];
        assert(!equal(d, Fq::zero()));
        assert(equal(divide(numerator, d) * d, numerator));
    }
}
// Numerator 0: the relation q * 0 = 0 holds for every q, so only the zero check rejects.
#[test(should_fail_with = "Zero denominator")]
fn divide_rejects_zero_denominator() {
    let _ = divide_with_quotient(fq(0), std::hint::black_box(Fq::zero()), fq(5));
}
// A wrong quotient dies in the BigNum relation hint before its constraint under
// honest execution; scripts/check_vendor_hints.py bypasses the hint.
#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn divide_rejects_noncanonical_zero_denominator() {
    let q = Fq::params().modulus;
    let _ = divide(fq(1), std::hint::black_box(Fq::from_limbs_unsafe(q)));
}
#[test]
fn nonsquare_certificate_sign_does_not_reach_output() {
    let mut hits = 0;
    for i in 0..8 {
        let u = std::hint::black_box(fq(i as Field));
        // Safety: honest hints and a negated certificate go through the checker.
        let (square, y, proof) = unsafe { swu_hint(u) };
        if !square {
            let a = swu_with_hints(u, square, y, proof);
            let b = swu_with_hints(u, square, y, -proof);
            assert(!equal(proof, -proof));
            assert(equal(a.x, b.x));
            assert(equal(a.y, b.y));
            hits += 1;
        }
    }
    assert(hits > 0);
}
