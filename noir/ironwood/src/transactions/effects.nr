use crate::transactions::digest::{V6Effects, txid_v6_bounded};

// These are authenticated effect bytes, not a plaintext/memo or ownership claim.
pub struct ActionEffect {
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub encrypted_note_prefix: [u8; 52],
}
// N is the Action capacity. The transaction has exactly action_count Actions,
// 1 <= action_count <= N, in slots 0..action_count; the other slots are zero.
// The compact digest hashes exactly 148 * action_count bytes, so the txid fixes
// action_count and every Action. DEPTH is the Merkle path capacity.
pub struct Inclusion<let N: u32, let DEPTH: u32> {
    pub effects: V6Effects<N>,
    pub header: [u8; 1487],
    pub siblings: [[u8; 32]; DEPTH],
    pub action_index: u32,
    pub tx_index: u32,
    pub tx_count: u32,
    pub action_count: u32,
}
// The remaining effect digests are opaque. The claim is "this transaction is in
// the block whose SHA256d is accepted_header_hash"; the block's height, network
// and ancestry are not bound here.
pub fn verify_transaction<let N: u32, let DEPTH: u32>(
    witness: Inclusion<N, DEPTH>,
    accepted_header_hash: [u8; 32],
) -> [u8; 32] {
    assert(
        crate::headers::header_hash(witness.header) == accepted_header_hash,
        "Header hash mismatch",
    );
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = witness.header[36 + i];
    }
    assert(witness.action_count > 0, "Inclusion needs at least one Action");
    let txid = txid_v6_bounded(witness.effects, witness.action_count);
    crate::transactions::merkle::verify(
        txid,
        witness.siblings,
        witness.tx_index,
        witness.tx_count,
        root,
    );
    txid
}
pub fn verify_action<let N: u32, let DEPTH: u32>(
    witness: Inclusion<N, DEPTH>,
    accepted_header_hash: [u8; 32],
) -> (ActionEffect, [u8; 32]) {
    assert(witness.action_index < witness.action_count, "Action index outside complete sequence");
    let txid = verify_transaction(witness, accepted_header_hash);
    let bytes = witness.effects.compact_actions[witness.action_index];
    let mut nullifier = [0u8; 32];
    let mut cmx = [0u8; 32];
    let mut ephemeral_key = [0u8; 32];
    let mut encrypted_note_prefix = [0u8; 52];
    for i in 0..32 {
        nullifier[i] = bytes[i];
        cmx[i] = bytes[32 + i];
        ephemeral_key[i] = bytes[64 + i];
    }
    for i in 0..52 {
        encrypted_note_prefix[i] = bytes[96 + i];
    }
    (ActionEffect { nullifier, cmx, ephemeral_key, encrypted_note_prefix }, txid)
}
pub fn verify_output<let N: u32, let DEPTH: u32>(
    witness: Inclusion<N, DEPTH>,
    accepted_header_hash: [u8; 32],
    expected_cmx: [u8; 32],
) -> (ActionEffect, [u8; 32]) {
    let (action, txid) = verify_action(witness, accepted_header_hash);
    assert(action.cmx == expected_cmx, "Output commitment mismatch");
    (action, txid)
}
