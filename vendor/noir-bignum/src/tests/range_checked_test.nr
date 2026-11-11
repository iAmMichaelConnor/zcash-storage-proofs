use crate::bignum::{BigNum, evaluate_quadratic_expression_prechecked, RangeChecked};
use crate::constants::TWO_POW_120;
use crate::fields::bn254Fq::BN254_Fq;

// a * b - c = 0 over range-checked terms, with c from the constrained `mul`.
#[test]
fn test_prechecked_quadratic_expression_accepts_product() {
    let a = BN254_Fq::from_limbs([3, 5, 7]);
    let b = BN254_Fq::from_limbs([11, 13, 17]);
    let c = a * b;
    evaluate_quadratic_expression_prechecked(
        [[RangeChecked::new(a)]],
        [[false]],
        [[RangeChecked::canonical(b)]],
        [[false]],
        [RangeChecked::new(c)],
        [true],
    );
}

// The same relation as `evaluate_quadratic_expression`, with constant terms.
#[test]
fn test_prechecked_quadratic_expression_constants() {
    let a = BN254_Fq::from_limbs([3, 5, 7]);
    // a * 1 + 0 - a = 0
    evaluate_quadratic_expression_prechecked(
        [[RangeChecked::new(a)]],
        [[false]],
        [[RangeChecked::one()]],
        [[false]],
        [RangeChecked::zero(), RangeChecked::new(a)],
        [false, true],
    );
    assert(RangeChecked::new(a).value() == a);
}

// A limb of 2^120 is outside the 120-bit limb range, so no RangeChecked value exists for it.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_range_checked_rejects_wide_limb() {
    let wide = BN254_Fq::from_limbs_unsafe([TWO_POW_120, 0, 0]);
    let _ = RangeChecked::new(wide);
}

// MOD + 1 has in-range limbs, so only the `validate_in_field` subtraction rejects it.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_range_checked_canonical_rejects_modulus_plus_one() {
    let limbs = BN254_Fq::modulus().get_limbs();
    let above = BN254_Fq::from_limbs_unsafe([limbs[0] + 1, limbs[1], limbs[2]]);
    let _ = RangeChecked::canonical(above);
}
