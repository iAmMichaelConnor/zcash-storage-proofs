// Optional full-body V4 coverage. Existing V5/V6 APIs remain usable without
// allocating legacy buffers. A valid V4 transaction is at least70 bytes: its
// fixed/count minimum29 plus a required input (41), Sapling spend (384), or
// JoinSplit (1698). Thus a Merkle internal node's64-byte preimage cannot be
// reinterpreted as a transaction. See docs/PROTOCOL.md.
use crate::transactions::digest::{NullifierAbsenceEffects, txid_asserting_nullifier_absence};
pub struct Effects<let A: u32, let RAW: u32> {
    pub effects: NullifierAbsenceEffects<A>,
    pub raw_v4: [u8; RAW],
    pub raw_length: u32,
}
pub fn v4_txid<let RAW: u32>(raw: [u8; RAW], length: u32) -> [u8; 32] {
    assert(RAW >= 70);
    assert(length >= 70, "V4 transaction below consensus minimum length");
    assert(length <= RAW, "V4 length exceeds raw buffer");
    let prefix = [4u8, 0, 0, 128, 133, 32, 47, 137];
    for i in 0..8 {
        assert(raw[i] == prefix[i], "Not an authenticated V4 transaction");
    }
    for i in 0..RAW {
        if i >= length {
            assert(raw[i] == 0, "Nonzero unused V4 byte");
        }
    }
    sha256::digest(sha256::sha256_var(raw, length))
}
// For a V4 row only raw_v4/raw_length are hashed; row.effects is meaningless and
// unconstrained (a V4 transaction has no Ironwood Actions). Inactive rows
// (i >= transaction_count) are never read. Zero padding there is a host
// convention, not a constraint: one statement can have several capsules.
pub fn txid<let A: u32, let RAW: u32>(row: Effects<A, RAW>, queried_nf: [u8; 32]) -> [u8; 32] {
    if row.effects.version == 4 {
        v4_txid(row.raw_v4, row.raw_length)
    } else {
        assert(row.raw_length == 0, "Raw V4 length on a non-V4 row");
        assert(row.raw_v4 == [0u8; RAW], "Raw V4 bytes on a non-V4 row");
        txid_asserting_nullifier_absence(row.effects, queried_nf)
    }
}
pub struct Block<let TX: u32, let A: u32, let RAW: u32> {
    pub header: [u8; 1487],
    pub transactions: [Effects<A, RAW>; TX],
    pub transaction_count: u32,
}
pub fn complete_block<let TX: u32, let A: u32, let RAW: u32>(
    block: Block<TX, A, RAW>,
    queried_nf: [u8; 32],
) -> [u8; 32] {
    assert(block.transaction_count > 0, "Mixed scan block has no transactions");
    assert(block.transaction_count <= TX, "Mixed scan block exceeds transaction capacity");
    let mut leaves = [[0u8; 32]; TX];
    for i in 0..TX {
        if i < block.transaction_count {
            leaves[i] = txid(block.transactions[i], queried_nf);
        }
    }
    let root = crate::transactions::merkle::complete_root(leaves, block.transaction_count);
    for i in 0..32 {
        assert(block.header[36 + i] == root[i], "Incomplete mixed transaction coverage");
    }
    crate::headers::header_hash(block.header)
}
// Same start, epoch and nullifier rules as nullifier_absence::from_activation.
pub fn from_activation<let B: u32, let TX: u32, let A: u32, let RAW: u32>(
    blocks: [Block<TX, A, RAW>; B],
    queried_nf: [u8; 32],
    expected_tip_hash: [u8; 32],
    expected_tip_height: u32,
    is_testnet: bool,
) {
    assert(B > 0);
    let start = crate::transactions::nullifier_absence::activation(is_testnet);
    assert(
        (start as u64) + (B as u64) - 1 == expected_tip_height as u64,
        "Scan must begin at Ironwood activation",
    );
    crate::transactions::nullifier_absence::assert_activation_start(
        blocks[0].header,
        queried_nf,
        expected_tip_height,
        is_testnet,
    );
    let mut previous = crate::transactions::nullifier_absence::pinned_prev(is_testnet);
    for i in 0..B {
        for j in 0..32 {
            assert(blocks[i].header[4 + j] == previous[j], "Broken scanned block link");
        }
        previous = complete_block(blocks[i], queried_nf);
    }
    assert(previous == expected_tip_hash, "Scan tip does not match accepted checkpoint");
}
