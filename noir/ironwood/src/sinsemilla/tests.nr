// Accepted exceptional inputs and rejected supplied hints for the crate-private
// Pallas helpers.
// Every vector is derived in the test from the pinned generators; none is typed in.
use bignum::{BigNum, Pallas_Fq as Fq};
use bigcurve::{BigCurve, Pallas};
use super::{
    check_fused_step, checked_point, complete_add, complete_add_hint, complete_add_with_hint,
    domain_q, domain_r, fused_step_hint, hash_to_point, hash_to_point_with_hints, HashPoint,
};

global TWO_POW_120: u128 = 0x1000000000000000000000000000000;

fn same(a: Pallas, b: Pallas) -> bool {
    (a.is_infinity() & b.is_infinity())
        | (
            !a.is_infinity()
                & !b.is_infinity()
                & (a.x.get_limbs() == b.x.get_limbs())
                & (a.y.get_limbs() == b.y.get_limbs())
        )
}

// The same integer with limb 0 raised by 2^120 and limb 1 lowered by one.
fn unnormalised(v: Fq) -> Fq {
    let limbs = v.get_limbs();
    assert(limbs[1] != 0);
    Fq::from_limbs_unsafe([limbs[0] + TWO_POW_120, limbs[1] - 1, limbs[2]])
}

#[test]
fn complete_add_accepts_equal_opposite_and_identity() {
    let p = std::hint::black_box(domain_r(0));
    let id = Pallas::point_at_infinity();
    let doubled = complete_add(p, p);
    assert(!doubled.is_infinity());
    doubled.validate_on_curve();
    assert(complete_add(p, -p).is_infinity());
    assert(same(complete_add(p, id), p));
    assert(same(complete_add(id, p), p));
    assert(complete_add(id, id).is_infinity());
    assert(same(complete_add(doubled, -p), p));
}

// Before the y != 0 check, (0,0)+(0,0) satisfied every relation for any slope l
// and returned the off-curve point (l^2, -l^3) chosen by the prover.
#[test(should_fail_with = "Doubling requires y != 0")]
fn complete_add_rejects_free_slope_at_zero_point() {
    let zero = Pallas::from_coordinates_unsafe(Fq::zero(), Fq::zero(), false);
    let l = std::hint::black_box(Fq::from(7));
    let _ = complete_add_with_hint(zero, zero, [l, l * l, -(l * l * l)]);
}

// The slope hint is canonical, so both its range and its field check reject this.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn complete_add_rejects_unnormalised_slope_limb() {
    let p = std::hint::black_box(domain_r(0));
    let q = domain_r(1);
    // Safety: the test supplies a malformed hint to the constrained checker.
    let h = unsafe { complete_add_hint(p, q) };
    let _ = complete_add_with_hint(p, q, [unnormalised(h[0]), h[1], h[2]]);
}

#[test]
fn check_fused_step_accepts_honest_hint() {
    let p = checked_point(std::hint::black_box(domain_q(0)));
    let s = HashPoint { point: domain_q(1), bottom: false };
    // Safety: the honest hint goes through the constrained checker.
    let h = unsafe { fused_step_hint(p, s) };
    let r = check_fused_step(p, s, h);
    assert(!r.bottom);
    r.point.validate_on_curve();
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn check_fused_step_rejects_unnormalised_slope_limb() {
    let p = checked_point(std::hint::black_box(domain_q(0)));
    let s = HashPoint { point: domain_q(1), bottom: false };
    // Safety: the test supplies a malformed hint to the constrained checker.
    let h = unsafe { fused_step_hint(p, s) };
    let _ = check_fused_step(p, s, [unnormalised(h[0]), h[1], h[2], h[3], h[4]]);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn check_fused_step_rejects_unnormalised_second_slope_limb() {
    let p = checked_point(std::hint::black_box(domain_q(0)));
    let s = HashPoint { point: domain_q(1), bottom: false };
    // Safety: the test supplies a malformed hint to the constrained checker.
    let h = unsafe { fused_step_hint(p, s) };
    let _ = check_fused_step(p, s, [h[0], h[1], unnormalised(h[2]), h[3], h[4]]);
}

// Honest hint records for hash_to_point_with_hints, as a host would supply them.
unconstrained fn hints_for<let N: u32>(
    q: Pallas,
    message: [bool; N],
) -> [[[u128; 3]; 5]; (N + 9) / 10] {
    let mut acc = HashPoint { point: q, bottom: false };
    let mut out = [[[0u128; 3]; 5]; (N + 9) / 10];
    for i in 0..(N + 9) / 10 {
        let mut index: u32 = 0;
        for b in 0..10 {
            if i * 10 + b < N {
                if message[i * 10 + b] {
                    index += 1u32 << b;
                }
            }
        }
        let s = HashPoint { point: super::generators::s(index as u16), bottom: false };
        let h = fused_step_hint(acc, s);
        for j in 0..5 {
            out[i][j] = h[j].get_limbs();
        }
        acc =
            HashPoint { point: Pallas::from_coordinates_unsafe(h[3], h[4], false), bottom: false };
    }
    out
}

fn hint_test_message() -> [bool; 20] {
    std::hint::black_box([
        true, false, true, true, false, false, true, false, true, true, false, true, false, false,
        false, true, true, false, true, false,
    ])
}

// The supplied-hint entry point computes the same point as the internal-hint one.
#[test]
fn supplied_hints_give_the_same_hash() {
    let message = hint_test_message();
    // Safety: the honest records go through the constrained checker.
    let hints = unsafe { hints_for(domain_q(0), message) };
    let internal = hash_to_point(domain_q(0), message);
    let supplied = hash_to_point_with_hints(domain_q(0), message, hints);
    assert(!internal.bottom & !supplied.bottom);
    assert(same(internal.point, supplied.point));
}

// A supplied record with another final x dies in the BigNum relation hint before
// the step's constraint under honest execution;
// scripts/check_vendor_hints.py bypasses the hint.
