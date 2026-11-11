// Ironwood V3 / transaction V6, pinned NU6.3 profile. A memo is bound to the
// complete encrypted Action and transaction ID, NOT by the note commitment.
// Newer transaction/memo bundle profiles require separate implementations.
pub mod aead;
pub mod diversifier;
mod constants;
use bignum::{BigNum, Pallas_Fr as Fr};
use crate::notes::{encode_nonidentity, NoteOpening};
use crate::transactions::effects::Inclusion;

// All Actions, in transaction order, in a buffer of N slots: the transaction
// has exactly action_count Actions (1 <= action_count <= N) and every later slot
// is all zero. cv, rk and outgoing ciphertext are opened as opaque committed
// bytes: this API does not validate spend authorisation or the transfer proof.
pub struct FullActionCiphertext {
    pub encrypted_note: [u8; 580],
    pub value_commitment: [u8; 32],
    pub randomized_key: [u8; 32],
    pub outgoing_ciphertext: [u8; 80],
}
// Recomputes the memo and noncompact digests over exactly action_count Actions.
// hash_bounded rejects nonzero bytes after the active Actions.
pub fn verify_ciphertext_digests<let N: u32>(
    effects: crate::transactions::digest::V6Effects<N>,
    action_count: u32,
    full: [FullActionCiphertext; N],
) {
    assert(N > 0, "Memo requires at least one Action");
    assert(action_count > 0, "Memo requires at least one Action");
    assert(action_count <= N, "Action count exceeds capacity");
    let mut memos = [0u8; 512 * N];
    let mut noncompact = [0u8; 160 * N];
    for a in 0..N {
        if a < action_count {
            for i in 0..52 {
                assert(
                    full[a].encrypted_note[i] == effects.compact_actions[a][96 + i],
                    "Compact ciphertext mismatch",
                );
            }
        } else {
            for i in 0..52 {
                assert(full[a].encrypted_note[i] == 0, "Nonzero unused Action ciphertext");
            }
        }
        for i in 0..512 {
            memos[512 * a + i] = full[a].encrypted_note[52 + i];
        }
        for i in 0..32 {
            noncompact[160 * a + i] = full[a].value_commitment[i];
            noncompact[160 * a + 32 + i] = full[a].randomized_key[i];
        }
        for i in 0..16 {
            noncompact[160 * a + 64 + i] = full[a].encrypted_note[564 + i];
        }
        for i in 0..80 {
            noncompact[160 * a + 80 + i] = full[a].outgoing_ciphertext[i];
        }
    }
    assert(
        crate::hashes::hash_bounded::<512 * N, 32>(
            memos,
            512 * action_count,
            "ZTxIdIrnActMH_v6".as_bytes(),
        )
            == effects.memos_digest,
        "Memo ciphertext digest mismatch",
    );
    assert(
        crate::hashes::hash_bounded::<160 * N, 32>(
            noncompact,
            160 * action_count,
            "ZTxIdIrnActNH_v6".as_bytes(),
        )
            == effects.noncompact_digest,
        "Noncompact Action digest mismatch",
    );
}
pub fn derive_esk(note: NoteOpening) -> Fr {
    let rho = note.rho.to_le_bytes();
    let mut input = [0u8; 65];
    for i in 0..32 {
        input[i] = note.rseed[i];
        input[33 + i] = rho[i];
    }
    input[32] = 4; // PrfExpand::ORCHARD_ESK, not the PSI or RCM domain.
    let esk: Fr = crate::notes::reduction::reduce512(crate::hashes::hash::<65, 64>(
        input,
        "Zcash_ExpandSeed".as_bytes(),
    ));
    assert(!esk.is_zero(), "Invalid note seed: zero ephemeral scalar");
    esk
}
// This low-level helper binds raw receiver, note-specific key and full AEAD.
// It does not by itself authenticate a note commitment or chain occurrence;
// use verify_memo_created_in_block for that complete composed claim.
pub fn verify_memo_from_opening(
    note: NoteOpening,
    raw_receiver: [u8; 43],
    ephemeral_key: [u8; 32],
    ciphertext: [u8; 580],
    memo: [u8; 512],
) {
    diversifier::verify_raw_receiver(raw_receiver, note.receiver);
    let esk = derive_esk(note);
    let epk = encode_nonidentity(crate::sinsemilla::scalar_mul(note.receiver.g_d, esk));
    assert(epk == ephemeral_key, "Ephemeral key does not match note randomness");
    let shared = encode_nonidentity(crate::sinsemilla::scalar_mul(note.receiver.pk_d, esk));
    let mut input = [0u8; 64];
    for i in 0..32 {
        input[i] = shared[i];
        input[32 + i] = epk[i];
    }
    let key = crate::hashes::hash::<64, 32>(input, "Zcash_OrchardKDF".as_bytes());
    let mut plaintext = [0u8; 564];
    plaintext[0] = 3;
    for i in 0..11 {
        plaintext[1 + i] = raw_receiver[i];
    }
    for i in 0..8 {
        plaintext[12 + i] = (note.value >> (8 * i) as u64) as u8;
    }
    for i in 0..32 {
        plaintext[20 + i] = note.rseed[i];
    }
    for i in 0..512 {
        plaintext[52 + i] = memo[i];
    }
    assert(
        aead::encrypt(key, plaintext) == ciphertext,
        "Memo ciphertext or authentication tag mismatch",
    );
}
// Key-free here means no wallet viewing/spending key. The private witness must
// contain this note's rseed and full ordered ciphertext digest preimages.
// The caller authenticates accepted_header_hash through application policy.
// Returns (txid, cmx). cmx is the selected Action's output note commitment,
// which verify_created_in_block checks against this note's commitment. Key a
// per-note application nullifier on cmx, not on txid or the block.
pub fn verify_memo_created_in_block<let N: u32, let DEPTH: u32>(
    note: NoteOpening,
    raw_receiver: [u8; 43],
    memo: [u8; 512],
    witness: Inclusion<N, DEPTH>,
    full: [FullActionCiphertext; N],
    accepted_header_hash: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    verify_ciphertext_digests(witness.effects, witness.action_count, full);
    let (action, txid) =
        crate::creation::verify_created_in_block(note, witness, accepted_header_hash);
    verify_memo_from_opening(
        note,
        raw_receiver,
        action.ephemeral_key,
        full[witness.action_index].encrypted_note,
        memo,
    );
    (txid, action.cmx)
}

mod aead_tests;

mod native_tests;

mod digest_tests;

mod claim_tests;

mod negative_tests;
