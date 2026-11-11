//! The scan state's logic (`scan::begin`, `scan::extend`, `scan::verify`, which the
//! contract's functions call) runs in private contexts at chosen addresses, with each
//! window in that address's capsule and each inserted note discovered before the next
//! context reads it. Each owner's notes are taken from the contract's `scans` storage
//! slot as the contract takes them.
use crate::fixture;
use aztec::{
    context::PrivateContext,
    note::NoteMessage,
    oracle::capsules,
    protocol::address::AztecAddress,
    state_vars::{Owned, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use nullifier_absence_state_contract::{
    IronwoodNullifierAbsenceState, nullifier_absence_note::NullifierAbsenceNote, scan,
};

global ADDRESS: AztecAddress = AztecAddress { inner: 0x1234 };

/// `self.storage.scans.at(owner)` of the contract running in `context`.
fn scans(context: &mut PrivateContext, owner: AztecAddress) -> scan::Scans {
    let scans: Owned<scan::Scans, &mut PrivateContext> = Owned::new(
        context,
        IronwoodNullifierAbsenceState::storage_layout().scans.slot,
    );
    scans.at(owner)
}

unconstrained fn stage(env: TestEnvironment, address: AztecAddress, window: [Field; 8910]) {
    env.utility_context_at(address, |_| {
        capsules::store(address, 67, window, AztecAddress::zero());
    });
}

/// Runs `scan::begin` at `address` and returns its note message undelivered.
unconstrained fn begin_message(
    env: TestEnvironment,
    address: AztecAddress,
    owner: AztecAddress,
    window: [Field; 8910],
    tip: [u8; 32],
    height: u32,
    count: u32,
) -> NoteMessage<NullifierAbsenceNote> {
    stage(env, address, window);
    env.private_context_at(address, |context| {
        scan::begin(
            scans(context, owner),
            address,
            fixture::NF,
            tip,
            height,
            false,
            count,
        )
    })
}

unconstrained fn begin(
    env: TestEnvironment,
    address: AztecAddress,
    owner: AztecAddress,
    window: [Field; 8910],
    tip: [u8; 32],
    height: u32,
    count: u32,
) {
    let message = begin_message(env, address, owner, window, tip, height, count);
    env.discover_note_at(address, message);
}

unconstrained fn extend(
    env: TestEnvironment,
    owner: AztecAddress,
    window: [Field; 8910],
    prior_height: u32,
    tip: [u8; 32],
    height: u32,
) {
    stage(env, ADDRESS, window);
    let message = env.private_context_at(ADDRESS, |context| {
        scan::extend(
            scans(context, owner),
            ADDRESS,
            fixture::NF,
            prior_height,
            tip,
            height,
            false,
            1,
        )
    });
    env.discover_note_at(ADDRESS, message);
}

unconstrained fn verify(
    env: TestEnvironment,
    address: AztecAddress,
    owner: AztecAddress,
    tip: [u8; 32],
    height: u32,
) -> bool {
    env.private_context_at(address, |context| {
        scan::verify(scans(context, owner), fixture::NF, tip, height, false)
    })
}

#[test]
unconstrained fn nullifier_absence_state_begin_extend_verify() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    assert(verify(env, ADDRESS, owner, fixture::FIRST, 3428143));
    extend(env, owner, fixture::NEXT, 3428143, fixture::SECOND, 3428144);
    assert(verify(env, ADDRESS, owner, fixture::SECOND, 3428144));
}

#[test(should_fail_with = "Authenticated scan checkpoint required")]
unconstrained fn missing_prior_note_rejected() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    assert(verify(env, ADDRESS, owner, fixture::FIRST, 3428143));
}

#[test(should_fail_with = "Authenticated prior scan note required")]
unconstrained fn cannot_extend_uninitialized_state() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    extend(env, owner, fixture::NEXT, 3428143, fixture::SECOND, 3428144);
}

#[test(should_fail_with = "Authenticated scan checkpoint required")]
unconstrained fn wrong_owner_cannot_read_nullifier_absence_state() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    let other = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    assert(verify(env, ADDRESS, other, fixture::FIRST, 3428143));
}

// verify selects the note by tip hash, so a substituted hash finds no
// note. Before begin succeeded, so this is not a capsule-setup failure.
#[test(should_fail_with = "Authenticated scan checkpoint required")]
unconstrained fn substituted_checkpoint_rejected() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    assert(verify(env, ADDRESS, owner, fixture::SECOND, 3428143));
}

#[test]
unconstrained fn initialize_two_block_window() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::SECOND,
        3428144,
        2,
    );
    assert(verify(env, ADDRESS, owner, fixture::SECOND, 3428144));
}

// Note hashes are siloed by contract address: the note message, delivered to another
// address too, yields no note there, because the note hash siloed with that address is
// not in the note hash tree.
#[test(should_fail_with = "Authenticated scan checkpoint required")]
unconstrained fn wrong_contract_cannot_read_nullifier_absence_state() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    let other = AztecAddress { inner: 0x5678 };
    let message = begin_message(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    env.discover_note_at(ADDRESS, message);
    env.discover_note_at(other, message);
    assert(verify(env, other, owner, fixture::FIRST, 3428143));
}

// Honest-lookup evidence only: verify proves that the note was created,
// not that it is unconsumed. A PXE that returns nullified notes makes this
// consumed checkpoint verify; it remains a true historical absence statement.
#[test(should_fail_with = "Authenticated scan checkpoint required")]
unconstrained fn consumed_nullifier_absence_state_is_not_reused() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    extend(env, owner, fixture::NEXT, 3428143, fixture::SECOND, 3428144);
    assert(verify(env, ADDRESS, owner, fixture::FIRST, 3428143));
}

// After a reorg the user holds an older note for the same nf and height on
// another lineage. The checkpoint of the newer lineage still verifies and extends.
#[test]
unconstrained fn same_height_lineages_verify_and_extend_independently() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    begin(
        env,
        ADDRESS,
        owner,
        fixture::INITIAL,
        fixture::FIRST,
        3428143,
        1,
    );
    begin(
        env,
        ADDRESS,
        owner,
        fixture::FORK_INITIAL,
        fixture::FORK_FIRST,
        3428143,
        1,
    );
    assert(verify(env, ADDRESS, owner, fixture::FORK_FIRST, 3428143));
    assert(verify(env, ADDRESS, owner, fixture::FIRST, 3428143));
    extend(
        env,
        owner,
        fixture::FORK_NEXT,
        3428143,
        fixture::FORK_SECOND,
        3428144,
    );
    assert(verify(env, ADDRESS, owner, fixture::FORK_SECOND, 3428144));
    // The other lineage's note was not consumed and still extends.
    extend(env, owner, fixture::NEXT, 3428143, fixture::SECOND, 3428144);
    assert(verify(env, ADDRESS, owner, fixture::SECOND, 3428144));
}

// A window that does not start at the pinned predecessor is refused.
#[test(should_fail_with = "Scan must link to pinned pre-activation block")]
unconstrained fn begin_from_unpinned_block_rejected() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();
    // NEXT starts with the second block: claiming it as the activation block skips the first.
    begin(
        env,
        ADDRESS,
        owner,
        fixture::NEXT,
        fixture::SECOND,
        3428143,
        1,
    );
}
