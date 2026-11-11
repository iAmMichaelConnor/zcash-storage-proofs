// The #[no_predicates] calling convention of ironwood::sinsemilla::merkle_root.
// Constrained only: unconstrained code does not execute a false branch at all.
use bignum::{BigNum, Pallas_Fq as Fq};
use ironwood::sinsemilla::merkle_root;

global TWO_POW_120: u128 = 0x1000000000000000000000000000000;

// #[no_predicates]: a false runtime branch does not disable the callee's checks.
// The unused leaf has a limb of 2^120, which fails its range constraint.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn no_predicates_call_is_enforced_on_false_branch() {
    let real = std::hint::black_box(false);
    let unused = Fq::from_limbs_unsafe([TWO_POW_120, 0, 0]);
    let root = if real {
        merkle_root::<1>(unused, 0, [Fq::zero()])
    } else {
        Fq::zero()
    };
    assert(root == Fq::zero());
}

// The documented pattern: select a valid dummy input, call unconditionally,
// then select the result.
#[test]
fn optional_slot_with_valid_dummy_is_accepted() {
    let real = std::hint::black_box(false);
    let unused = Fq::from_limbs_unsafe([TWO_POW_120, 0, 0]);
    let leaf = if real { unused } else { Fq::zero() };
    let computed = merkle_root::<1>(leaf, 0, [Fq::zero()]);
    let root = if real { computed } else { Fq::zero() };
    assert(root == Fq::zero());
}
