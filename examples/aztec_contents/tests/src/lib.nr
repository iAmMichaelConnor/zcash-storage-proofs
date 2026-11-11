//! Tests of IronwoodPrivateContents' logic in TXE test contexts: `verify_contents` (the body of
//! `verify`) runs in a private context at a chosen address, with the witnesses of the note_value
//! example's fixture in that address's capsules.
use aztec::{
    oracle::capsules, protocol::address::AztecAddress,
    test::helpers::test_environment::TestEnvironment,
};
use aztec_contents_contract::verify_contents;
use note_value_test::fixture;

global ADDRESS: AztecAddress = AztecAddress { inner: 0x1234 };

/// Stores `header` (unless empty) and `note` in the claim-0 capsules of ADDRESS and runs
/// `verify_contents` there for the checkpoint (`hash`, the fixture height, mainnet).
unconstrained fn verify<let H: u32>(
    header: [Field; H],
    note: [Field; 145],
    hash: [u8; 32],
) -> ([u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3], u32) {
    let env = TestEnvironment::new();
    env.utility_context_at(ADDRESS, |_| {
        if H > 0 {
            capsules::store(ADDRESS, 60, header, AztecAddress::zero());
        }
        capsules::store(ADDRESS, 61, note, AztecAddress::zero());
    });
    env.private_context_at(ADDRESS, |_| verify_contents(ADDRESS, hash, fixture::HEIGHT, false))
}

#[test]
unconstrained fn note_contents_returned() {
    let (cmx, value, receiver, rho, height) = verify(fixture::HEADER, fixture::NOTE, fixture::HASH);
    assert_eq(cmx, fixture::CMX);
    assert_eq(value, fixture::VALUE);
    // The note capsule starts with the opening: g_d and pk_d (x and y limbs), value, rho.
    for p in 0..2 {
        for c in 0..2 {
            for i in 0..3 {
                assert_eq(receiver[p][c][i] as Field, fixture::NOTE[6 * p + 3 * c + i]);
            }
        }
    }
    for i in 0..3 {
        assert_eq(rho[i] as Field, fixture::NOTE[13 + i]);
    }
    // The checkpoint's root covers the notes through the block before the header.
    assert_eq(height, fixture::HEIGHT - 1);
}

#[test(should_fail_with = "Header hash mismatch")]
unconstrained fn other_checkpoint_rejected() {
    let mut hash = fixture::HASH;
    hash[0] = hash[0] ^ 1;
    let _ = verify(fixture::HEADER, fixture::NOTE, hash);
}

#[test(should_fail_with = "Ironwood note membership failed")]
unconstrained fn altered_path_rejected() {
    // The low limb of the first sibling, after the opening (48 fields) and the position.
    let mut note = fixture::NOTE;
    note[49] = note[49] + 1;
    let _ = verify(fixture::HEADER, note, fixture::HASH);
}

#[test(should_fail_with = "Missing Ironwood witness capsule")]
unconstrained fn missing_header_capsule_rejected() {
    let _ = verify([], fixture::NOTE, fixture::HASH);
}
