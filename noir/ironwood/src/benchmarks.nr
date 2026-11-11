// Benchmark entry points: one #[export] function per claim, at the capacities the
// README uses (one Action per transaction and a 32-level transaction Merkle path;
// the absence scan at two blocks of four transactions with two Actions each).
// `nargo export --package ironwood` compiles each to its own program for the gates report.
use crate::{BigNum, Pallas_Fq};
use crate::memo::FullActionCiphertext;
use crate::notes::{ExpandedReceiver, NoteOpening};
use crate::notes::ownership::{SpendAuthority, ViewingAuthority};
use crate::transactions::effects::Inclusion;

#[export]
fn note_membership(
    note: NoteOpening,
    position: u32,
    siblings: [Pallas_Fq; 32],
    accepted_root: [u8; 32],
) {
    crate::notes::verify_contents_membership(
        note,
        position,
        siblings,
        Pallas_Fq::from_le_bytes(accepted_root),
    );
}

#[export]
fn spending_authority(receiver: ExpandedReceiver, authority: SpendAuthority) {
    crate::notes::ownership::verify(receiver, authority);
}

#[export]
fn linked_nullifier(note: NoteOpening, authority: ViewingAuthority) -> ([u8; 32], [u8; 32]) {
    let (cmx, nf) = crate::notes::nullifier::derive_with_commitment(note, authority);
    (cmx.to_le_bytes(), nf.to_le_bytes())
}

#[export]
fn header_history(
    header: [u8; 1487],
    node: [u8; 317],
    auth_root: [u8; 32],
    accepted_header_hash: [u8; 32],
    header_height: u32,
    is_testnet: bool,
) -> ([u8; 32], u32) {
    let snapshot = crate::headers::verify_header_latest(
        header,
        accepted_header_hash,
        header_height,
        is_testnet,
        node,
        auth_root,
    );
    (snapshot.root, snapshot.height)
}

#[export]
fn nullifier_inclusion(
    witness: Inclusion<1, 32>,
    nullifier: [u8; 32],
    accepted_header_hash: [u8; 32],
) {
    crate::transactions::verify_nullifier_inclusion(witness, nullifier, accepted_header_hash);
}

#[export]
fn created_in_block(
    note: NoteOpening,
    witness: Inclusion<1, 32>,
    accepted_header_hash: [u8; 32],
) -> [u8; 32] {
    crate::creation::verify_created_in_block(note, witness, accepted_header_hash).1
}

#[export]
fn memo_created_in_block(
    note: NoteOpening,
    raw_receiver: [u8; 43],
    memo: [u8; 512],
    witness: Inclusion<1, 32>,
    full: [FullActionCiphertext; 1],
    accepted_header_hash: [u8; 32],
) -> ([u8; 32], [u8; 32]) {
    crate::memo::verify_memo_created_in_block(
        note,
        raw_receiver,
        memo,
        witness,
        full,
        accepted_header_hash,
    )
}

#[export]
fn nullifier_absence_2_blocks(
    blocks: [u8; 6830],
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) {
    let blocks = crate::transactions::encoding::blocks::<2, 4, 2, 6830>(blocks);
    crate::transactions::nullifier_absence::from_activation(
        blocks,
        queried_nf,
        expected_tip_hash,
        expected_tip_height,
        is_testnet,
    );
}
