use aztec::protocol::address::AztecAddress;
use bignum::BigNum;
use ironwood::transactions::{V6Effects, effects::{ActionEffect, Inclusion}};

fn u32le<let L: u32>(bytes: [u8; L], offset: u32) -> u32 {
    let mut value = 0u32;
    for i in 0..4 {
        value = value | ((bytes[offset + i] as u32) << (8 * i));
    }
    value
}
// Slot68: header, N Action slots, memo/noncompact digests, flags, balance,
// three other-pool digests, lock/expiry, siblings, action index, tx index,
// tx count, action count. Each capsule element represents exactly one byte.
// N is the Action capacity: the transaction has exactly action_count Actions
// and the later slots are zero (the bounded compact hash checks both).
// Load each capsule once per claim. A second load of slot 60, 61, 68, 69 or 103
// for the same claim is a new unconstrained witness that a PXE can answer with
// a different note or transaction: use the values these functions return.
// `claim` selects the claim's slots (crate::claim_slot); see the slot table.
pub fn inclusion<let N: u32, let DEPTH: u32>(
    address: AztecAddress,
    claim: u32,
) -> Inclusion<N, DEPTH> {
    // Safety: every element is byte checked here; verify_action constrains the
    // header hash, the txid over exactly action_count Actions and the path.
    let raw = unsafe {
        crate::load::<1680 + 148 * N + 32 * DEPTH>(
            address,
            crate::claim_slot(crate::INCLUSION_SLOT, claim),
        )
    };
    let mut bytes = [0u8; 1680 + 148 * N + 32 * DEPTH];
    for i in 0..bytes.len() {
        raw[i].assert_max_bit_size::<8>();
        bytes[i] = raw[i] as u8;
    }
    let mut header = [0u8; 1487];
    for i in 0..1487 {
        header[i] = bytes[i];
    }
    let mut compact_actions = [[0u8; 148]; N];
    for i in 0..N {
        for j in 0..148 {
            compact_actions[i][j] = bytes[1487 + 148 * i + j];
        }
    }
    let offset = 1487 + 148 * N;
    let mut memos_digest = [0u8; 32];
    let mut noncompact_digest = [0u8; 32];
    let mut value_balance = [0u8; 8];
    for i in 0..32 {
        memos_digest[i] = bytes[offset + i];
        noncompact_digest[i] = bytes[offset + 32 + i];
    }
    for i in 0..8 {
        value_balance[i] = bytes[offset + 65 + i];
    }
    let mut other = [[0u8; 32]; 3];
    for i in 0..3 {
        for j in 0..32 {
            other[i][j] = bytes[offset + 73 + 32 * i + j];
        }
    }
    let effects = V6Effects {
        compact_actions,
        memos_digest,
        noncompact_digest,
        flags: bytes[offset + 64],
        value_balance,
        transparent_digest: other[0],
        sapling_digest: other[1],
        orchard_digest: other[2],
        lock_time: u32le(bytes, offset + 169),
        expiry_height: u32le(bytes, offset + 173),
    };
    let mut siblings = [[0u8; 32]; DEPTH];
    for i in 0..DEPTH {
        for j in 0..32 {
            siblings[i][j] = bytes[offset + 177 + 32 * i + j];
        }
    }
    let end = offset + 177 + 32 * DEPTH;
    Inclusion {
        effects,
        header,
        siblings,
        action_index: u32le(bytes, end),
        tx_index: u32le(bytes, end + 4),
        tx_count: u32le(bytes, end + 8),
        action_count: u32le(bytes, end + 12),
    }
}
// Slot69 is only the 48-field key-free note opening: no Merkle path or wallet key.
pub fn opening(address: AztecAddress, claim: u32) -> ironwood::notes::NoteOpening {
    // Safety: decode_opening bounds every field; the caller binds the opening to
    // the Action output through NoteCommit and rho.
    let raw = unsafe { crate::load::<48>(address, crate::claim_slot(crate::OPENING_SLOT, claim)) };
    crate::decode_opening(raw)
}
pub fn verify_action<let N: u32, let DEPTH: u32>(
    address: AztecAddress,
    claim: u32,
    accepted_header_hash: [u8; 32],
) -> (ActionEffect, [u8; 32]) {
    ironwood::transactions::effects::verify_action(
        inclusion::<N, DEPTH>(address, claim),
        accepted_header_hash,
    )
}
// Proves "an output with this opening was created in the block whose SHA256d is
// accepted_header_hash". It does NOT prove that the receiver can decrypt or
// spend the output: epk and ciphertext are opaque txid inputs, and consensus
// accepts undecryptable outputs (the Ironwood builder makes some on purpose).
// A deposit must use ironwood_aztec::memo::verify, which also checks the note
// encryption. The block's height, network and ancestry are not bound.
pub fn verify_created<let N: u32, let DEPTH: u32>(
    address: AztecAddress,
    claim: u32,
    accepted_header_hash: [u8; 32],
) -> ([u8; 32], [u8; 32], u64, [[[u128; 3]; 2]; 2], [u128; 3]) {
    let note = opening(address, claim);
    let (action, txid) = ironwood::creation::verify_created_in_block(
        note,
        inclusion::<N, DEPTH>(address, claim),
        accepted_header_hash,
    );
    (
        action.cmx, txid, note.value,
        [
            [note.receiver.g_d.x.get_limbs(), note.receiver.g_d.y.get_limbs()],
            [note.receiver.pk_d.x.get_limbs(), note.receiver.pk_d.y.get_limbs()],
        ], note.rho.get_limbs(),
    )
}
