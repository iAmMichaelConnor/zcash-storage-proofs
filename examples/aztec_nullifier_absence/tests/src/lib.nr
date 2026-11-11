//! Tests of IronwoodNullifierAbsence's logic in TXE test contexts: `verify_absence` (the body of
//! `verify`) runs in a private context at a chosen address, with the complete blocks of
//! `fixture.nr` in that address's slot-63 capsule.
mod fixture;

use aztec::{
    oracle::capsules, protocol::address::AztecAddress,
    test::helpers::test_environment::TestEnvironment,
};
use aztec_nullifier_absence_contract::verify_absence;

global ADDRESS: AztecAddress = AztecAddress { inner: 0x1234 };

/// Stores `blocks` (unless empty) in the slot-63 capsule of ADDRESS and runs `verify_absence`
/// there for `nf` and the tip (`tip`, `height`, mainnet).
unconstrained fn verify<let N: u32>(blocks: [Field; N], nf: [u8; 32], tip: [u8; 32], height: u32) {
    let env = TestEnvironment::new();
    if N > 0 {
        env.utility_context_at(ADDRESS, |_| {
            capsules::store(ADDRESS, 63, blocks, AztecAddress::zero());
        });
    }
    env.private_context_at(ADDRESS, |_| verify_absence(ADDRESS, nf, tip, height, false));
}

#[test]
unconstrained fn absent_nullifier_accepted() {
    verify(
        fixture::BLOCKS,
        fixture::NF,
        fixture::TIP,
        fixture::TIP_HEIGHT,
    );
}

#[test(should_fail_with = "Queried nullifier occurs in scanned transaction")]
unconstrained fn spent_nullifier_rejected() {
    verify(
        fixture::BLOCKS,
        fixture::SPENT_NF,
        fixture::TIP,
        fixture::TIP_HEIGHT,
    );
}

#[test(should_fail_with = "Scan tip does not match accepted checkpoint")]
unconstrained fn other_tip_rejected() {
    let mut tip = fixture::TIP;
    tip[0] = tip[0] ^ 1;
    verify(fixture::BLOCKS, fixture::NF, tip, fixture::TIP_HEIGHT);
}

#[test(should_fail_with = "Scan must begin at Ironwood activation")]
unconstrained fn other_tip_height_rejected() {
    // Two blocks from activation end at activation + 1.
    verify(
        fixture::BLOCKS,
        fixture::NF,
        fixture::TIP,
        fixture::TIP_HEIGHT + 1,
    );
}

#[test(should_fail_with = "call to assert_max_bit_size")]
unconstrained fn non_byte_capsule_value_rejected() {
    let mut blocks = fixture::BLOCKS;
    blocks[0] = 256;
    verify(blocks, fixture::NF, fixture::TIP, fixture::TIP_HEIGHT);
}

#[test(should_fail_with = "Missing complete Ironwood scan capsule")]
unconstrained fn missing_capsule_rejected() {
    verify([], fixture::NF, fixture::TIP, fixture::TIP_HEIGHT);
}
