//! The IronwoodPrivateContentsCapsules tests that compute the Sinsemilla hints for all 32 levels
//! of the note's path, about two minutes each: `scripts/test-examples.sh --slow` runs them, and the
//! nightly workflow does. The setup is that of ../tests.
use aztec_contents_capsules_test::{stage, verify};
use note_value_test::fixture;

#[test]
unconstrained fn note_contents_returned_with_supplied_hints() {
    let (cmx, value, _, _, height) = verify(stage(fixture::NOTE, 32));
    assert_eq(cmx, fixture::CMX);
    assert_eq(value, fixture::VALUE);
    assert_eq(height, fixture::HEIGHT - 1);
}

#[test(should_fail_with = "Ironwood note membership failed")]
unconstrained fn altered_note_value_rejected_with_honest_hints() {
    // The hints are honest for the altered note, so only the root comparison rejects it.
    let mut note = fixture::NOTE;
    note[12] = note[12] + 1;
    let _ = verify(stage(note, 32));
}
