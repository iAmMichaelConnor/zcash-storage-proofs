use crate::notes::NoteOpening;
use crate::transactions::effects::{Inclusion, ActionEffect};
use bignum::BigNum;

// Key-free opening of an output committed by an accepted block's transaction.
// Unlike cumulative membership, this binds the exact creation block. The caller
// authenticates its hash/network/height through application chain policy.
// No wallet key, raw-address derivation, memo or unspent claim is implied.
pub fn verify_created_in_block<let N: u32, let DEPTH: u32>(
    note: NoteOpening,
    witness: Inclusion<N, DEPTH>,
    accepted_header_hash: [u8; 32],
) -> (ActionEffect, [u8; 32]) {
    let cmx = crate::notes::commitment_x(note);
    let (action, txid) = crate::transactions::effects::verify_output(
        witness,
        accepted_header_hash,
        cmx.to_le_bytes(),
    );
    // An Action's new note rho is the old note's nullifier (not arbitrary input).
    assert(note.rho.to_le_bytes() == action.nullifier, "Output rho must match Action nullifier");
    (action, txid)
}
