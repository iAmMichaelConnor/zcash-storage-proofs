use aztec::{
    context::PrivateContext,
    note::{note_getter_options::NoteGetterOptions, note_interface::NoteProperties, NoteMessage},
    protocol::address::AztecAddress,
    state_vars::PrivateSet,
    utils::comparison::Comparator,
};
use crate::nullifier_absence_note::{halves, NullifierAbsenceNote};

/// One owner's scan notes in the contract's private storage.
pub type Scans = PrivateSet<NullifierAbsenceNote, &mut PrivateContext>;

/// Scans the window in the capsule of `address` from Ironwood activation and inserts
/// the resulting note. The caller delivers the returned message.
pub fn begin(
    scans: Scans,
    address: AztecAddress,
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
    count: u32,
) -> NoteMessage<NullifierAbsenceNote> {
    let next = ironwood::transactions::nullifier_absence_state::initialize(
        crate::capsule::blocks(address),
        count,
        queried_nf,
        expected_tip_hash,
        expected_tip_height,
        is_testnet,
    );
    scans.insert(NullifierAbsenceNote::from_state(next))
}

/// Consumes the note for (nf, prior height, prior tip hash, network), where the prior
/// tip hash is the parent hash of the first block in the capsule window, scans the
/// window and inserts the advanced note. The caller delivers the returned message.
pub fn extend(
    scans: Scans,
    address: AztecAddress,
    queried_nf: [u8; 32],
    prior_height: u32,
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
    count: u32,
) -> NoteMessage<NullifierAbsenceNote> {
    let blocks = crate::capsule::blocks(address);
    let mut prior_tip = [0u8; 32];
    for j in 0..32 {
        prior_tip[j] = blocks[0].header[4 + j];
    }
    let nf = halves(queried_nf);
    let tip = halves(prior_tip);
    let found = scans.pop_notes(NoteGetterOptions::new()
        .select(NullifierAbsenceNote::properties().nf_lo, Comparator.EQ, nf[0])
        .select(NullifierAbsenceNote::properties().nf_hi, Comparator.EQ, nf[1])
        .select(NullifierAbsenceNote::properties().hash_lo, Comparator.EQ, tip[0])
        .select(NullifierAbsenceNote::properties().hash_hi, Comparator.EQ, tip[1])
        .select(NullifierAbsenceNote::properties().height, Comparator.EQ, prior_height)
        .select(NullifierAbsenceNote::properties().is_testnet, Comparator.EQ, is_testnet)
        .set_limit(1));
    assert(found.len() == 1, "Authenticated prior scan note required");
    let prior = found.get(0).state();
    assert(prior.is_testnet == is_testnet);
    assert(prior.queried_nf == queried_nf);
    assert(prior.tip_hash == prior_tip);
    let next = ironwood::transactions::nullifier_absence_state::advance(
        prior,
        blocks,
        count,
        expected_tip_hash,
        expected_tip_height,
    );
    scans.insert(NullifierAbsenceNote::from_state(next))
}

/// Reads, without consuming, the note for (nf, tip hash, height, network).
pub fn verify(
    scans: Scans,
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) -> bool {
    let nf = halves(queried_nf);
    let tip = halves(expected_tip_hash);
    let found = scans.get_notes(NoteGetterOptions::new()
        .select(NullifierAbsenceNote::properties().nf_lo, Comparator.EQ, nf[0])
        .select(NullifierAbsenceNote::properties().nf_hi, Comparator.EQ, nf[1])
        .select(NullifierAbsenceNote::properties().hash_lo, Comparator.EQ, tip[0])
        .select(NullifierAbsenceNote::properties().hash_hi, Comparator.EQ, tip[1])
        .select(NullifierAbsenceNote::properties().height, Comparator.EQ, expected_tip_height)
        .select(NullifierAbsenceNote::properties().is_testnet, Comparator.EQ, is_testnet)
        .set_limit(1));
    assert(found.len() == 1, "Authenticated scan checkpoint required");
    let state = found.get(0).note.state();
    assert(state.queried_nf == queried_nf);
    assert(state.tip_hash == expected_tip_hash);
    assert(state.height == expected_tip_height);
    assert(state.is_testnet == is_testnet);
    assert(
        state.activation_height
            == ironwood::transactions::nullifier_absence_state::activation(is_testnet),
    );
    true
}
