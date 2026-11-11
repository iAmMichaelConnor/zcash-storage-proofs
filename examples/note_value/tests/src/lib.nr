//! Generated note witnesses exercise actual membership and the application policy:
//! `check_note` (the body of `accept`) runs in a private context at a chosen address,
//! with the witnesses in that address's capsules, and `count_acceptance` (the body of
//! `record_acceptance`) in a public context at that address.
pub mod fixture;
use aztec::{
    oracle::capsules,
    protocol::address::AztecAddress,
    state_vars::{PublicMutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use note_value_contract::{check_note, count_acceptance, IronwoodContentsApplication, Policy};

global ADDRESS: AztecAddress = AztecAddress { inner: 0x1234 };

fn policy(minimum_value: u64) -> Policy {
    Policy {
        checkpoint_hash: fixture::HASH,
        checkpoint_height: fixture::HEIGHT,
        is_testnet: false,
        minimum_value,
    }
}

unconstrained fn check(minimum_value: u64, corrupt: bool) -> TestEnvironment {
    let env = TestEnvironment::new();
    let mut note = fixture::NOTE;
    if corrupt {
        note[12] = note[12] + 1;
    }
    env.utility_context_at(ADDRESS, |_| {
        capsules::store(ADDRESS, 60, fixture::HEADER, AztecAddress::zero());
        capsules::store(ADDRESS, 61, note, AztecAddress::zero());
    });
    env.private_context_at(ADDRESS, |_| check_note(ADDRESS, policy(minimum_value)));
    env
}

#[test]
unconstrained fn note_at_the_application_minimum_accepted_and_counted() {
    let env = check(fixture::VALUE, false);
    env.public_context_at(ADDRESS, |context| {
        let accepted = PublicMutable::new(
            context,
            IronwoodContentsApplication::storage_layout().accepted.slot,
        );
        assert_eq(accepted.read(), 0);
        count_acceptance(accepted);
        assert_eq(accepted.read(), 1);
        count_acceptance(accepted);
        assert_eq(accepted.read(), 2);
    });
}

#[test(should_fail_with = "Note value is below application minimum")]
unconstrained fn below_application_minimum_rejected() {
    let _ = check(fixture::VALUE + 1, false);
}

#[test(should_fail_with = "Ironwood note membership failed")]
unconstrained fn altered_note_value_rejected() {
    let _ = check(0, true);
}
